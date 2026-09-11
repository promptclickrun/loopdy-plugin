"""Adapter-owned direct lifecycle, enrollment and immutable request ownership.

No listener is opened at plugin discovery. HTTPS is supplied externally; this
module never configures Tailscale, redirects credentials, or starts Hermes.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import time
from typing import Any, Callable, Mapping, TYPE_CHECKING
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import weakref

from cryptography.hazmat.primitives import serialization

from .direct_commands import DirectCommandJournal
from .direct_connection import DirectConnectionAuthority
if TYPE_CHECKING:
    from .direct_server import DirectRequestContext
from .inbound_dispatch import AuthenticatedRequestOwner, ReplyRoute
from .session_stream import SessionStreamHub

DIRECT_ENROLLMENT_CAPABILITY = "direct-enrollment-v1"
_MAX_CATALOG_BYTES = 256 * 1024


@dataclass(frozen=True)
class DirectSettings:
    enabled: bool = False
    origin: str = ""
    port: int = 0

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "DirectSettings":
        if not isinstance(values, Mapping) or set(values) - {"enabled", "origin", "port"}:
            raise ValueError("direct configuration fields are invalid")
        enabled = values.get("enabled", False)
        if type(enabled) is not bool:
            raise ValueError("direct.enabled must be a boolean")
        origin, port = values.get("origin", ""), values.get("port", 0)
        if type(port) is not int:
            raise ValueError("direct.port must be an integer")
        if not enabled and origin == "" and port == 0:
            return cls()
        if (not isinstance(origin, str) or not origin or len(origin) > 512
                or any(c.isspace() or ord(c) < 32 for c in origin)
                or any(c in origin for c in ("\\", "?", "#"))):
            raise ValueError("direct.origin must be an explicit HTTPS origin")
        try:
            parsed = urlsplit(origin)
            valid = (parsed.scheme == "https" and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and parsed.path == "" and parsed.query == "" and parsed.fragment == ""
                     and (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("direct.origin must be an explicit HTTPS origin without credentials or a path")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("direct.port must be a fixed port from 1 through 65535")
        return cls(enabled, origin, port)

    def as_mapping(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "origin": self.origin, "port": self.port}


def runtime_owner(config: Any) -> tuple[Any, ...]:
    key = config.signing_private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return (config.base_url, config.device_id, config.authorization_epoch,
            hashlib.sha256(key).hexdigest(), hashlib.sha256(config.account_key).hexdigest())


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate catalog key")
        result[key] = value
    return result


def fetch_lifecycle_catalog(config: Any) -> dict[str, Any]:
    """One signed HTTPS GET, bounded bytes/depth/time, no redirects."""
    path = "/v1/devices"
    request = Request(config.base_url + path, method="GET", headers={
        **config.signed_headers(method="GET", path=path, body=""),
        "Accept": "application/json",
    })
    with build_opener(_NoRedirect()).open(request, timeout=8) as response:
        if response.status != 200:
            raise ValueError("catalog response status is invalid")
        data = response.read(_MAX_CATALOG_BYTES + 1)
    if len(data) > _MAX_CATALOG_BYTES:
        raise ValueError("catalog response is too large")
    def reject(_value):
        raise ValueError("non-finite catalog number")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=reject)
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > 12:
            raise ValueError("catalog response is too deep")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


class DirectRuntime:
    """One immutable authority/journal/hub per adapter connection generation."""
    def __init__(self, *, settings: DirectSettings, config: Any, state: Any,
                 journal_path: Path, dispatch: Callable, open_session: Callable | None = None,
                 config_getter: Callable | None = None, settings_getter: Callable | None = None,
                 catalog_fetcher: Callable = fetch_lifecycle_catalog,
                 monotonic: Callable = time.monotonic,
                 status_callback: Callable | None = None,
                 hub: SessionStreamHub | None = None):
        settings = DirectSettings.from_mapping(settings.as_mapping())
        if not settings.enabled:
            raise ValueError("direct runtime is disabled")
        self.settings, self.config, self.state = settings, config, state
        self.generation = secrets.token_urlsafe(24)
        self._owner = runtime_owner(config)
        self._configuration_revision = state.get("direct.configuration_revision", None)
        self._config_getter, self._settings_getter = config_getter, settings_getter
        self._catalog_fetcher, self._monotonic = catalog_fetcher, monotonic
        self._refresh_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task | None = None
        self._retired = False
        self._closed = False
        self._status_callback = status_callback
        self._last_available = None
        self._started = False
        self._refreshed_at: float | None = None
        self._catalog: dict[str, dict] = {}
        self._subscriptions: weakref.WeakSet = weakref.WeakSet()
        self.authority = DirectConnectionAuthority(
            account_origin=config.base_url, direct_origin=settings.origin,
            host_device_id=config.device_id, host_epoch=config.authorization_epoch,
            host_private_key=config.signing_private_key, state=state, monotonic=monotonic)
        # Import the optional listener dependency before opening durable state.
        from .direct_server import DirectServer
        self.journal = DirectCommandJournal(journal_path)
        self.hub = hub if hub is not None else SessionStreamHub(
            maximum_events=128, maximum_bytes=262_144, maximum_subscriptions=64)
        # The server validates through this lifecycle facade, not the raw
        # authority, so local unpair/config changes also retire live sockets.
        self.server = DirectServer(self, self.journal, dispatch=dispatch, open_session=open_session)

    def _check_owner(self) -> None:
        if self._retired:
            raise ConnectionError("direct owner retired")
        try:
            if self.state.get("direct.configuration_revision", None) != self._configuration_revision:
                raise ValueError("direct configuration changed")
            if self._config_getter is not None:
                current = self._config_getter()
                if current is None or runtime_owner(current) != self._owner:
                    raise ValueError("paired owner changed")
            if self._settings_getter is not None and self._settings_getter() != self.settings:
                raise ValueError("direct settings changed")
        except Exception:
            self._retired = True
            raise ConnectionError("direct owner changed") from None

    def check_current(self) -> None:
        self._check_owner()
        if self._refreshed_at is None or self._monotonic() - self._refreshed_at > 300:
            raise ConnectionError("direct lifecycle authorization is stale")
        host = self._catalog.get(self.config.device_id)
        if not self._active(host, "host", self.config.authorization_epoch):
            raise ConnectionError("direct host authorization is unavailable")

    @staticmethod
    def _active(row, role, epoch):
        return bool(row and row["role"] == role and row["lifecycle"] == "active"
                    and row["revokedAt"] is None and row["authorizationEpoch"] == epoch)

    def retire(self) -> None:
        """Deny admission synchronously; the owned lifecycle task closes sockets."""
        self._retired = True
        self._notify_availability()

    @property
    def retired(self) -> bool:
        return self._retired

    @property
    def available(self) -> bool:
        try:
            self.check_current()
            return self._started
        except (ValueError, ConnectionError):
            return False

    def status(self) -> dict[str, Any]:
        return {"enabled": True, "available": self.available,
                "state": "ready" if self.available else "unavailable",
                "origin": self.settings.origin, "port": self.settings.port,
                "generation": self.generation}

    async def start(self) -> None:
        try:
            await self.refresh()
            self.check_current()
            await self.server.start(port=self.settings.port)
            self._started = True
            self._notify_availability()
            self._refresh_task = asyncio.create_task(self._refresh_loop(), name="loopdy-direct-lifecycle")
        except BaseException:
            await self.stop()
            raise

    async def refresh(self) -> None:
        async with self._refresh_lock:
            self._check_owner()
            try:
                catalog = await asyncio.to_thread(self._catalog_fetcher, self.config)
            except HTTPError as error:
                if error.code in {401, 403, 404, 410}:
                    self._retired = True
                    self._refreshed_at = None
                raise
            self._check_owner()
            # Parsing/denial persistence precedes publication; failures do not
            # extend freshness. Catalog revocation is monotonic in the authority.
            try:
                self.authority._refresh_lifecycle_catalog(catalog)
            except Exception:
                self._refreshed_at = None
                raise
            self._catalog = {row["deviceId"]: dict(row) for row in catalog["devices"]}
            if not self._active(self._catalog.get(self.config.device_id), "host", self.config.authorization_epoch):
                self._retired = True
                self._refreshed_at = None
                raise ConnectionError("direct host authorization retired")
            self._refreshed_at = self._monotonic()

    def _notify_availability(self):
        available = self.available
        state = (available, self._retired)
        if state != self._last_available:
            self._last_available = state
            if self._status_callback is not None:
                try:
                    self._status_callback(self, available)
                except Exception:
                    # UI diagnostics cannot keep retired sockets admitted.
                    pass

    async def _refresh_loop(self) -> None:
        next_refresh = self._monotonic() + 60
        while self._started:
            await asyncio.sleep(1)
            self._notify_availability()
            if self._retired:
                await self.stop()
                return
            if self._monotonic() < next_refresh:
                continue
            next_refresh = self._monotonic() + 60
            try:
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A network failure never renews the lease.
                pass
            self._notify_availability()
            if self._retired:
                await self.stop()
                return

    def issue_challenge(self, **kwargs):
        self.check_current()
        return self.authority.issue_challenge(**kwargs)

    def verify_challenge_response(self, **kwargs):
        self.check_current()
        return self.authority.verify_challenge_response(**kwargs)

    def validate_peer(self, peer):
        self.check_current()
        return self.authority.validate_peer(peer)

    async def enroll(self, payload: Mapping[str, Any], *, sender_device_id: str,
                     sender_epoch: int) -> dict[str, Any]:
        await self.refresh()
        self.check_current()
        if not self._active(self._catalog.get(sender_device_id), "mobile", sender_epoch):
            raise ValueError("enrolling peer lifecycle is unavailable")
        return self.authority._enroll_from_link(payload,
            trusted_sender_device_id=sender_device_id, trusted_sender_epoch=sender_epoch)

    def reply_route(self, context: DirectRequestContext) -> ReplyRoute:
        self.validate_peer(context.peer)
        peer = context.peer
        from .wiki_transport import authority_id
        owner = AuthenticatedRequestOwner(
            authority_id(self.config), peer.host_device_id, peer.host_epoch,
            peer.peer_device_id, peer.peer_epoch, self.generation,
            "direct", context.connection_id)
        return ReplyRoute(owner, lambda: self.validate_peer(peer), context.send)

    def subscribe(self, *, agent_id: str, session_id: str):
        self.check_current()
        feed = self.hub.subscribe(agent_id=agent_id, session_id=session_id)
        self._subscriptions.add(feed)
        return feed

    async def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._retired = True
        self._started = False
        self._refreshed_at = None
        task, self._refresh_task = self._refresh_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        try:
            await self.server.stop()
        finally:
            for feed in tuple(self._subscriptions):
                feed.close()
            self._subscriptions.clear()
            self.journal.close()
            self._notify_availability()
