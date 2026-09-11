"""Plugin-owned authenticated reply leases; no gateway or transport mutation."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
import secrets


class AttachmentUnavailable(ValueError):
    def __init__(self, message):
        super().__init__("The attached file is unavailable. Attach it again and retry.")
        self.message = message


def parse_authenticated_payload(client, payload, *, sender_device_id, sender_epoch,
                                target_host_id=None, target_device_id=None):
    """Shared domain parser. Callers authenticate first and retain their own WAL.

    No synthetic encrypted frame, receipt, socket or sequence is constructed.
    Unknown envelope fields reach the existing strict domain decoders unchanged.
    """
    from . import link_client as types
    from . import link_contracts as contracts
    from .wiki_transport import authority_id

    kind = payload.get("type")
    if kind == "attachment.chunk":
        client.attachment_inbox.accept(sender_device_id=sender_device_id,
                                      chunk=contracts.parse_attachment_chunk(payload))
        return None
    if kind == "user.message":
        message = contracts.parse_user_message(payload)
        try:
            sender_id = client.identity_registry.remember(
                sender_device_id=sender_device_id, actor_id=message.actor_id,
                actor_name=message.actor_name, device_name=message.device_name)
            paths, media_types = client.attachment_inbox.resolve(
                sender_device_id=sender_device_id, session_id=message.session_id,
                agent_id=message.agent_id, references=message.attachments)
        except (OSError, ValueError) as error:
            raise AttachmentUnavailable(message) from error
        return types.InboundLinkTurn(
            message=message, sender_id=sender_id, sender_device_id=sender_device_id,
            attachment_paths=paths, attachment_types=media_types,
            sender_epoch=sender_epoch, target_host_id=target_host_id or client.config.device_id,
            authority_origin=types._link_authority_origin(client.config))
    if kind == "relay.ready":
        registration = contracts.parse_relay_ready(payload)
        if registration.device_id != sender_device_id:
            raise ValueError("relay device does not match the authenticated sender")
        if types._expired_host_relay(registration):
            raise contracts.ExpiredHostRelayEnrollment("host-relay enrollment has expired")
        return types.InboundLinkRelayReady(registration, sender_device_id, sender_epoch)
    if kind == "session.fork.request":
        request = contracts.parse_session_fork_request(payload)
        sender_id = client.identity_registry.remember(
            sender_device_id=sender_device_id, actor_id=request.actor_id,
            actor_name=request.actor_name, device_name=request.device_name)
        return types.InboundLinkSessionFork(request, sender_id, sender_device_id, sender_epoch)
    if kind == "workspace.request":
        request = contracts.parse_workspace_request(payload)
        return types.InboundLinkWorkspaceRequest(
            request=request, sender_device_id=sender_device_id,
            target_host_id=target_host_id, sender_epoch=sender_epoch,
            authority_id=authority_id(client.config)
            if request.operation in contracts.AVAILABLE_WIKI_OPERATIONS else None)
    if kind in {"device.tools.status", "device.tool.result"}:
        if target_device_id != client.config.device_id:
            raise ValueError("device tool target is invalid")
        parser, constructor = (
            (contracts.parse_device_tool_status, types.InboundLinkDeviceToolStatus)
            if kind == "device.tools.status" else
            (contracts.parse_device_tool_result, types.InboundLinkDeviceToolResult))
        return constructor(parser(payload, sender_device_id=sender_device_id,
                                  sender_epoch=sender_epoch),
                           sender_device_id, sender_epoch, target_device_id)
    if kind == "direct.enroll":
        if target_host_id != client.config.device_id or target_device_id != client.config.device_id:
            raise ValueError("direct enrollment requires a directed host target")
        enrollment = contracts.parse_direct_enrollment(payload)
        return types.InboundLinkDirectEnrollment(enrollment, sender_device_id, sender_epoch)
    decoders = {
        "voice.speak.request": (contracts.parse_voice_speak_request, types.InboundLinkVoiceSpeak),
        "picker.open": (contracts.parse_picker_open, types.InboundLinkPickerOpen),
        "picker.select": (contracts.parse_picker_selection, types.InboundLinkPickerSelection),
        "commands.catalog.request": (contracts.parse_command_catalog_request, types.InboundLinkCommandCatalog),
        "personalities.catalog.request": (contracts.parse_personality_request, types.InboundLinkPersonalityRequest),
        "personalities.mutate": (contracts.parse_personality_request, types.InboundLinkPersonalityRequest),
        "generative.ui.form.submit": (contracts.parse_generative_ui_form_submission, types.InboundLinkGenerativeUIFormSubmission),
    }
    if kind not in decoders:
        raise ValueError("Loopdy payload type is unsupported")
    parser, constructor = decoders[kind]
    return constructor(parser(payload), sender_device_id, sender_epoch)


class DirectResponseCapture:
    """Return one synchronous domain result; late work uses the original socket.

    A ContextVar alone is not ownership: the exact ingress task must also match.
    Child tasks retain the immutable route but can never append to this result.
    """
    def __init__(self, route):
        self.original = route
        self.task = asyncio.current_task()
        self.result = None
        self.closed = False

    async def send(self, payload):
        if not self.closed and asyncio.current_task() is self.task and self.result is None:
            self.result = payload
            return self.original.owner.connection_id
        return await self.original.send(payload)

    def route(self):
        return ReplyRoute(self.original.owner, self.original.check_current, self.send)

    def finish(self):
        self.closed = True
        return self.result or {"version": 1, "type": "direct.dispatched", "status": "accepted"}


@dataclass(frozen=True)
class AuthenticatedRequestOwner:
    account_id: str
    host_id: str
    host_epoch: int
    device_id: str
    device_epoch: int
    generation: str
    transport: str
    connection_id: str


@dataclass(frozen=True)
class ReplyRoute:
    owner: AuthenticatedRequestOwner
    check_current: Callable[[], None] = field(repr=False, compare=False)
    sender: Callable[[dict[str, Any]], Awaitable[Any]] = field(repr=False, compare=False)

    async def send(self, payload: dict[str, Any]) -> str:
        self.check_current()
        result = await self.sender(payload)
        self.check_current()
        return str(result or self.owner.connection_id)


current_reply_route: ContextVar[ReplyRoute | None] = ContextVar(
    "loopdy_reply_route", default=None
)


@dataclass(frozen=True)
class TurnReplyLease:
    profile: str
    session_id: str
    message_id: str
    generation: str
    route: ReplyRoute


class TurnReplyRegistry:
    """Exact originating-message routes, retained beyond ingress task lifetime.

    Never evict an active lease into relay fallback. Capacity rejects new work.
    The callback's inherited lease (when present) must match the registry entry;
    a newer run cannot inherit the old run's connection or vice versa.
    """
    def __init__(self, maximum: int = 512):
        self.maximum = maximum
        self._leases: dict[tuple[str, str, str], TurnReplyLease] = {}
        self._direct_sessions: set[tuple[str, str]] = set()

    def register(self, profile: str, session_id: str, message_id: str,
                 route: ReplyRoute) -> TurnReplyLease:
        key = (profile, session_id, message_id)
        if key in self._leases:
            raise ValueError("originating message already owns a reply route")
        if (len(self._leases) >= self.maximum or
                ((profile, session_id) not in self._direct_sessions
                 and route.owner.transport == "direct" and len(self._direct_sessions) >= self.maximum)):
            raise ValueError("reply route capacity exhausted")
        original = route
        def check():
            if self._leases.get(key) is not lease:
                raise ConnectionError("turn reply owner retired")
            original.check_current()
        route = ReplyRoute(original.owner, check, original.sender)
        lease = TurnReplyLease(*key, secrets.token_urlsafe(18), route)
        self._leases[key] = lease
        if route.owner.transport == "direct":
            self._direct_sessions.add((profile, session_id))
        return lease

    def resolve(self, profile: str, session_id: str, message_id: str | None,
                inherited: TurnReplyLease | None = None) -> ReplyRoute | None:
        if inherited is not None:
            if (inherited.profile != profile or inherited.session_id != session_id
                    or (message_id and inherited.message_id != message_id)):
                raise ConnectionError("response turn owner mismatch")
            key = (profile, session_id, inherited.message_id)
            if self._leases.get(key) is not inherited:
                raise ConnectionError("response turn retired")
            return inherited.route
        if message_id:
            lease = self._leases.get((profile, session_id, message_id))
            if lease is not None:
                return lease.route
        if (profile, session_id) in self._direct_sessions:
            raise ConnectionError("direct response requires exact originating message")
        return None

    def lookup(self, profile, session_id, message_id):
        return self._leases.get((profile, session_id, message_id))

    def complete(self, lease: TurnReplyLease) -> None:
        key = (lease.profile, lease.session_id, lease.message_id)
        if self._leases.get(key) is lease:
            self._leases.pop(key)
        # Retain bounded session fences: late callbacks must fail, not broadcast.

    def clear(self) -> None:
        self._leases.clear()
        # Keep direct-session fences across adapter reconnects. A late callback
        # without a lease must never become a new legacy broadcast.


current_turn_lease: ContextVar[TurnReplyLease | None] = ContextVar(
    "loopdy_turn_reply_lease", default=None
)
