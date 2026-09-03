"""Portable outbound Loopdy Link WebSocket runtime for Hermes."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .link_contracts import (
    AttachmentChunk,
    CommandCatalogRequest,
    EncryptedFrame,
    GenerativeUIFormSubmission,
    MAX_ENCRYPTED_FRAME_CHARACTERS,
    PersonalityRequest,
    PickerOpen,
    PickerSelection,
    RelayReady,
    SessionForkRequest,
    UserMessage,
    VoiceSpeakRequest,
    WorkspaceRequest,
    parse_attachment_chunk,
    parse_encrypted_frame,
    parse_generative_ui_form_submission,
    parse_command_catalog_request,
    parse_personality_request,
    parse_picker_open,
    parse_picker_selection,
    parse_relay_ready,
    parse_session_fork_request,
    parse_user_message,
    parse_voice_speak_request,
    parse_workspace_request,
)
from .link_attachments import LinkAttachmentInbox
from .link_crypto import (
    AccountCipher,
    decode_base64url,
    encode_base64url,
    sign_p256_raw,
)
from .link_identity import LinkIdentityRegistry


logger = logging.getLogger("hermes.plugins.loopdy.link")
_SOCKET_PATH = "/v1/socket"
_PROCESS_TRANSPORT_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_TRANSPORT_LOCKS_GUARD = threading.Lock()


class _MemoryState:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.values[key] = value


def _transport_lock_path(state: Any, device_id: str) -> Path:
    try:
        data_dir = Path(state.data_dir)
    except (AttributeError, TypeError, ValueError):
        data_dir = Path(tempfile.gettempdir()) / "loopdy-link" / "transport-locks"
    coordinate = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
    return data_dir / "transport-locks" / f"{coordinate}.lock"


class _LoopdyLinkTransportLock:
    """Portable per-device lock protecting the durable Link sequence transaction."""

    def __init__(self, path: Path):
        self.path = path
        self._handle: Any | None = None
        self._process_lock: threading.Lock | None = None

    async def __aenter__(self) -> "_LoopdyLinkTransportLock":
        acquisition = asyncio.create_task(asyncio.to_thread(self._acquire_blocking))
        try:
            await asyncio.shield(acquisition)
        except asyncio.CancelledError:
            await acquisition
            self._release_blocking()
            raise
        return self

    async def __aexit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self._release_blocking()

    def _acquire_blocking(self) -> None:
        key = str(self.path.resolve())
        with _PROCESS_TRANSPORT_LOCKS_GUARD:
            process_lock = _PROCESS_TRANSPORT_LOCKS.setdefault(key, threading.Lock())
        process_lock.acquire()
        handle: Any | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = open(self.path, "a+b")
            if os.name == "nt":  # pragma: no cover - exercised on Windows CI
                import msvcrt

                if handle.seek(0, os.SEEK_END) == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            self._handle = handle
            self._process_lock = process_lock
        except BaseException:
            if handle is not None:
                handle.close()
            process_lock.release()
            raise

    def _release_blocking(self) -> None:
        handle, self._handle = self._handle, None
        process_lock, self._process_lock = self._process_lock, None
        if handle is None or process_lock is None:
            return
        try:
            if os.name == "nt":  # pragma: no cover - exercised on Windows CI
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            process_lock.release()


@dataclass(frozen=True)
class LinkRuntimeConfig:
    base_url: str
    device_id: str
    authorization_epoch: int
    signing_private_key: ec.EllipticCurvePrivateKey
    account_key: bytes

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> "LinkRuntimeConfig":
        required = (
            "LOOPDY_LINK_BASE_URL",
            "LOOPDY_LINK_DEVICE_ID",
            "LOOPDY_LINK_AUTHORIZATION_EPOCH",
            "LOOPDY_LINK_SIGNING_PRIVATE_KEY",
            "LOOPDY_LINK_ACCOUNT_KEY",
        )
        missing = [key for key in required if not str(values.get(key) or "").strip()]
        if missing:
            raise ValueError("Loopdy Link configuration is incomplete")
        base_url = _validated_origin(str(values["LOOPDY_LINK_BASE_URL"]))
        device_id = _opaque(str(values["LOOPDY_LINK_DEVICE_ID"]), 1, 96)
        try:
            epoch = int(values["LOOPDY_LINK_AUTHORIZATION_EPOCH"])
        except (TypeError, ValueError) as exc:
            raise ValueError("Loopdy Link authorization epoch is invalid") from exc
        if epoch < 1:
            raise ValueError("Loopdy Link authorization epoch is invalid")
        key_value = serialization.load_der_private_key(
            decode_base64url(
                str(values["LOOPDY_LINK_SIGNING_PRIVATE_KEY"]),
                minimum=100,
                maximum=512,
            ),
            password=None,
        )
        if not isinstance(key_value, ec.EllipticCurvePrivateKey) or not isinstance(
            key_value.curve, ec.SECP256R1
        ):
            raise ValueError("Loopdy Link signing key is invalid")
        account_key = decode_base64url(
            str(values["LOOPDY_LINK_ACCOUNT_KEY"]), minimum=32, maximum=32
        )
        return cls(
            base_url=base_url,
            device_id=device_id,
            authorization_epoch=epoch,
            signing_private_key=key_value,
            account_key=account_key,
        )

    @property
    def socket_url(self) -> str:
        return "wss://" + self.base_url.removeprefix("https://") + _SOCKET_PATH

    def signed_headers(
        self,
        *,
        method: str,
        path: str,
        body: str,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> dict[str, str]:
        now = int(time.time()) if timestamp is None else int(timestamp)
        nonce_value = nonce or encode_base64url(os.urandom(24))
        canonical = canonical_device_request(
            method=method,
            path=path,
            device_id=self.device_id,
            timestamp=now,
            nonce=nonce_value,
            authorization_epoch=self.authorization_epoch,
            body=body,
        )
        return {
            "x-loopdy-device-id": self.device_id,
            "x-loopdy-timestamp": str(now),
            "x-loopdy-nonce": nonce_value,
            "x-loopdy-authorization-epoch": str(self.authorization_epoch),
            "x-loopdy-signature": encode_base64url(
                sign_p256_raw(self.signing_private_key, canonical.encode("utf-8"))
            ),
        }


@dataclass(frozen=True)
class InboundLinkTurn:
    message: UserMessage
    sender_id: str
    sender_device_id: str
    attachment_paths: tuple[str, ...] = ()
    attachment_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class _InboundLinkTurnFailure:
    message: UserMessage
    code: str
    detail: str


@dataclass(frozen=True)
class InboundLinkRelayReady:
    registration: RelayReady
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkVoiceSpeak:
    request: VoiceSpeakRequest
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkPickerOpen:
    request: PickerOpen
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkPickerSelection:
    selection: PickerSelection
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkSessionFork:
    request: SessionForkRequest
    sender_id: str
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkCommandCatalog:
    request: CommandCatalogRequest
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkPersonalityRequest:
    request: PersonalityRequest
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkGenerativeUIFormSubmission:
    request: GenerativeUIFormSubmission
    sender_device_id: str


@dataclass(frozen=True)
class InboundLinkWorkspaceRequest:
    request: WorkspaceRequest
    sender_device_id: str


def canonical_device_request(
    *,
    method: str,
    path: str,
    device_id: str,
    timestamp: int,
    nonce: str,
    authorization_epoch: int,
    body: str,
) -> str:
    body_digest = encode_base64url(hashlib.sha256(body.encode("utf-8")).digest())
    return "\n".join(
        (
            "loopdy-link-device-v1",
            method.upper(),
            path,
            device_id,
            str(timestamp),
            nonce,
            str(authorization_epoch),
            body_digest,
        )
    )


class LoopdyLinkClient:
    """One asyncio-owned reconnecting Link connection per Hermes adapter."""

    _TRANSPORT_STATE_SUFFIXES = (
        "outbound_sequence",
        "pending_frame",
        "failed_pending_frame_id",
        "received_sequences",
        "last_received_sequence",
    )

    def __init__(
        self,
        config: LinkRuntimeConfig,
        *,
        state: Any | None = None,
        attachment_root: Path | None = None,
        delivery_timeout: float = 20.0,
        readiness_timeout: float = 15.0,
    ):
        self.config = config
        self.state = state or _MemoryState()
        self._transport_state_prefix = f"link.transport.{config.device_id}"
        self._migrate_legacy_transport_state()
        self.cipher = AccountCipher(config.account_key)
        self.identity_registry = LinkIdentityRegistry(
            self.state, account_key=config.account_key
        )
        default_attachment_root = (
            Path(tempfile.gettempdir())
            / "loopdy-link"
            / hashlib.sha256(config.device_id.encode("utf-8")).hexdigest()
        )
        self.attachment_inbox = LinkAttachmentInbox(
            attachment_root or default_attachment_root
        )
        self._task: asyncio.Task | None = None
        self._socket: Any = None
        self._connected = asyncio.Event()
        self._stopping = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._transport_lock = _LoopdyLinkTransportLock(
            _transport_lock_path(self.state, config.device_id)
        )
        self._delivery_timeout = max(0.001, float(delivery_timeout))
        self._readiness_timeout = max(0.001, float(readiness_timeout))
        self._accepted: dict[str, asyncio.Future[None]] = {}
        self._live_activity_accepted: dict[str, asyncio.Future[None]] = {}
        self._inbound_callback_queue: asyncio.Queue[
            tuple[Callable[[Any], Any], EncryptedFrame, Any]
        ] = asyncio.Queue()
        self._inbound_callback_task: asyncio.Task[None] | None = None
        self._last_error = ""
        self._reconnect_attempt = 0
        self._superseded = False
        self._status_callback: Callable[[str, str], Any] | None = None

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def status(self) -> dict[str, Any]:
        return {
            "configured": True,
            "state": (
                "connected"
                if self.connected
                else "superseded" if self._superseded else "disconnected"
            ),
            "base_url": self.config.base_url,
            "device_id": self.config.device_id,
            "authorization_epoch": self.config.authorization_epoch,
            "reconnect_attempt": self._reconnect_attempt,
            "detail": self._last_error[:160],
        }

    def release_attachment_paths(self, paths: Iterable[str]) -> None:
        """Release verified Link media after Hermes finishes its background turn."""
        self.attachment_inbox.discard(paths)

    def start(
        self,
        callback: Callable[
            [
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
            ],
            Any,
        ],
        *,
        status_callback: Callable[[str, str], Any] | None = None,
    ) -> None:
        if self._task is not None and not self._task.done():
            return
        if self._superseded:
            self._record_runtime_status("superseded", self._last_error)
            return
        self._status_callback = status_callback
        self._stopping.clear()
        self._record_runtime_status("connecting")
        self._task = asyncio.create_task(
            self._run(callback), name="loopdy-link-connection"
        )

    async def wait_until_connected(self, *, timeout: float = 20.0) -> bool:
        """Wait for the verified socket.ready handshake, not task startup."""
        if self.connected:
            return True
        if self._stopping.is_set():
            return False
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return self.connected

    async def stop(self) -> None:
        self._stopping.set()
        self._connected.clear()
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
        socket, self._socket = self._socket, None
        if socket is not None:
            try:
                await asyncio.wait_for(
                    socket.close(code=1000, reason="Hermes stopping"),
                    timeout=0.25,
                )
            except Exception:
                pass
        if task is not None and not task.done():
            await asyncio.gather(task, return_exceptions=True)
        for future in self._accepted.values():
            if not future.done():
                future.cancel()
        self._accepted.clear()
        for future in self._live_activity_accepted.values():
            if not future.done():
                future.cancel()
        self._live_activity_accepted.clear()
        await self._stop_inbound_callback_dispatcher()
        self._record_runtime_status("disconnected")

    async def send_payload(self, payload: dict[str, Any]) -> str:
        async with self._send_lock:
            await asyncio.wait_for(self._connected.wait(), timeout=20.0)
            async with self._transport_lock:
                await self._wait_for_prior_pending()
                sequence = int(self._transport_get("outbound_sequence", 0) or 0) + 1
                frame = EncryptedFrame(
                    frame_id="frame_" + encode_base64url(os.urandom(18)),
                    sender_device_id=self.config.device_id,
                    sender_epoch=self.config.authorization_epoch,
                    sequence=sequence,
                    ack=int(self._transport_get("last_received_sequence", 0) or 0),
                    ciphertext=self.cipher.seal(payload),
                )
                wire = frame.wire_value()
                self._transport_set("pending_frame", wire)
                loop = asyncio.get_running_loop()
                accepted: asyncio.Future[None] = loop.create_future()
                self._accepted[frame.frame_id] = accepted
                await self._send_wire(wire)
                try:
                    await asyncio.wait_for(
                        asyncio.shield(accepted), timeout=self._delivery_timeout
                    )
                except asyncio.TimeoutError:
                    await self._mark_failed_outbound_and_reconnect(frame)
                    raise
                finally:
                    self._accepted.pop(frame.frame_id, None)
                return frame.frame_id

    def pending_payload_frame_id(self, payload: dict[str, Any]) -> str | None:
        """Return the durable frame owning this exact payload, if one exists."""
        wire = self._transport_get("pending_frame")
        if not isinstance(wire, dict):
            return None
        try:
            frame = parse_encrypted_frame(json.dumps(wire, separators=(",", ":")))
            pending_payload = self.cipher.open(frame.ciphertext)
        except (TypeError, ValueError):
            return None
        return frame.frame_id if pending_payload == payload else None

    async def send_live_activity_update(self, payload: dict[str, Any]) -> str:
        """Send the deliberately server-readable, sanitized ActivityKit projection."""

        update = _validated_live_activity_update(payload)
        update_id = str(update["updateId"])
        async with self._send_lock:
            await asyncio.wait_for(self._connected.wait(), timeout=20.0)
            loop = asyncio.get_running_loop()
            accepted: asyncio.Future[None] = loop.create_future()
            self._live_activity_accepted[update_id] = accepted
            await self._send_wire(update)
            try:
                await asyncio.wait_for(asyncio.shield(accepted), timeout=20.0)
            finally:
                self._live_activity_accepted.pop(update_id, None)
        return update_id

    async def handle_wire_message(
        self,
        encoded: str,
        callback: Callable[
            [
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
            ],
            Any,
        ],
        *,
        defer_callbacks: bool = False,
    ) -> bool:
        try:
            header = json.loads(encoded)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Loopdy Link socket message is invalid") from exc
        if (
            isinstance(header, dict)
            and header.get("version") == 1
            and header.get("type") == "socket.ready"
        ):
            self._reconcile_socket_ready(header)
            return True
        self._record_runtime_status("connected")
        if isinstance(header, dict) and header.get("version") == 1 and header.get("type") == "accepted":
            self._accept_outbound(header)
            return False
        if (
            isinstance(header, dict)
            and header.get("version") == 1
            and header.get("type") == "receipt.accepted"
        ):
            return False
        if (
            isinstance(header, dict)
            and header.get("version") == 1
            and header.get("type") == "live_activity.accepted"
        ):
            self._accept_live_activity(header)
            return False
        frame = parse_encrypted_frame(encoded)
        sequences = self._transport_get("received_sequences", {})
        sequence_map = dict(sequences) if isinstance(sequences, dict) else {}
        has_previous = frame.sender_device_id in sequence_map
        previous = int(sequence_map.get(frame.sender_device_id, 0) or 0)
        if not defer_callbacks:
            if has_previous and frame.sequence <= previous:
                await self._send_receipt(frame)
                return False
            if has_previous and frame.sequence != previous + 1:
                raise ValueError("Loopdy Link inbound sequence is invalid")
        payload = self.cipher.open(frame.ciphertext)
        target_host_id = payload.pop("targetHostId", None)
        if target_host_id is not None:
            if (
                not isinstance(target_host_id, str)
                or not 1 <= len(target_host_id) <= 96
                or any(
                    not character.isascii()
                    or not (character.isalnum() or character in "_-")
                    for character in target_host_id
                )
            ):
                raise ValueError("Loopdy Link target host is invalid")
            if target_host_id != self.config.device_id:
                if defer_callbacks:
                    self._enqueue_inbound_callback(callback, frame, None)
                else:
                    await self._accept_inbound_frame(frame)
                return False
        inbound: (
            InboundLinkTurn
            | _InboundLinkTurnFailure
            | InboundLinkRelayReady
            | InboundLinkVoiceSpeak
            | InboundLinkPickerOpen
            | InboundLinkPickerSelection
            | InboundLinkSessionFork
            | InboundLinkCommandCatalog
            | InboundLinkPersonalityRequest
            | InboundLinkGenerativeUIFormSubmission
            | InboundLinkWorkspaceRequest
            | None
        )
        if payload.get("type") == "attachment.chunk":
            try:
                chunk: AttachmentChunk = parse_attachment_chunk(payload)
                self.attachment_inbox.accept(
                    sender_device_id=frame.sender_device_id,
                    chunk=chunk,
                )
            except (OSError, ValueError) as exc:
                await self._quarantine_inbound_payload(frame, exc)
                return False
            inbound = None
        elif payload.get("type") == "user.message":
            try:
                message = parse_user_message(payload)
            except ValueError as exc:
                await self._quarantine_inbound_payload(frame, exc)
                return False
            try:
                sender_id = self.identity_registry.remember(
                    sender_device_id=frame.sender_device_id,
                    actor_id=message.actor_id,
                    actor_name=message.actor_name,
                    device_name=message.device_name,
                )
                attachment_paths, attachment_types = self.attachment_inbox.resolve(
                    sender_device_id=frame.sender_device_id,
                    session_id=message.session_id,
                    agent_id=message.agent_id,
                    references=message.attachments,
                )
            except (OSError, ValueError) as exc:
                logger.warning(
                    "Loopdy Link inbound message attachment is unavailable (%s)",
                    _connection_error_detail(exc),
                )
                if defer_callbacks:
                    self._enqueue_inbound_callback(
                        callback,
                        frame,
                        _InboundLinkTurnFailure(
                            message=message,
                            code="attachment_unavailable",
                            detail=(
                                "The attached file is unavailable. "
                                "Attach it again and retry."
                            ),
                        ),
                    )
                    return False
                try:
                    await self._send_user_message_result(
                        message,
                        status="failed",
                        code="attachment_unavailable",
                        message="The attached file is unavailable. Attach it again and retry.",
                    )
                    await self._accept_inbound_frame(frame)
                except Exception as delivery_error:
                    logger.warning(
                        "Loopdy Link could not deliver the correlated attachment failure (%s)",
                        _connection_error_detail(delivery_error),
                    )
                    await self._close_for_reconnect(
                        "correlated attachment failure delivery failed"
                    )
                return False
            inbound = InboundLinkTurn(
                message=message,
                sender_id=sender_id,
                sender_device_id=frame.sender_device_id,
                attachment_paths=attachment_paths,
                attachment_types=attachment_types,
            )
        elif payload.get("type") == "relay.ready":
            registration = parse_relay_ready(payload)
            if registration.device_id != frame.sender_device_id:
                raise ValueError("Loopdy Link relay device does not match the verified sender")
            inbound = InboundLinkRelayReady(
                registration=registration,
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "voice.speak.request":
            inbound = InboundLinkVoiceSpeak(
                request=parse_voice_speak_request(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "picker.open":
            inbound = InboundLinkPickerOpen(
                request=parse_picker_open(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "picker.select":
            inbound = InboundLinkPickerSelection(
                selection=parse_picker_selection(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "session.fork.request":
            request = parse_session_fork_request(payload)
            sender_id = self.identity_registry.remember(
                sender_device_id=frame.sender_device_id,
                actor_id=request.actor_id,
                actor_name=request.actor_name,
                device_name=request.device_name,
            )
            inbound = InboundLinkSessionFork(
                request=request,
                sender_id=sender_id,
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "commands.catalog.request":
            inbound = InboundLinkCommandCatalog(
                request=parse_command_catalog_request(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") in {
            "personalities.catalog.request",
            "personalities.mutate",
        }:
            inbound = InboundLinkPersonalityRequest(
                request=parse_personality_request(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "generative.ui.form.submit":
            inbound = InboundLinkGenerativeUIFormSubmission(
                request=parse_generative_ui_form_submission(payload),
                sender_device_id=frame.sender_device_id,
            )
        elif payload.get("type") == "workspace.request":
            inbound = InboundLinkWorkspaceRequest(
                request=parse_workspace_request(payload),
                sender_device_id=frame.sender_device_id,
            )
        else:
            raise ValueError("Loopdy Link payload type is invalid")
        if defer_callbacks:
            self._enqueue_inbound_callback(callback, frame, inbound)
            return False

        if inbound is not None:
            result = callback(inbound)
            if inspect.isawaitable(result):
                await result
        sequence_map[frame.sender_device_id] = frame.sequence
        self._transport_set("received_sequences", sequence_map)
        self._transport_set(
            "last_received_sequence",
            max(int(self._transport_get("last_received_sequence", 0) or 0), frame.sequence),
        )
        await self._send_receipt(frame)
        return False

    async def _run(
        self,
        callback: Callable[
            [
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
            ],
            Any,
        ],
    ) -> None:
        try:
            from websockets.asyncio.client import connect
        except Exception as exc:
            self._last_error = "The websockets dependency is unavailable"
            self._record_runtime_status("configuration_error", self._last_error)
            logger.error("Loopdy Link cannot start: %s", self._last_error)
            return
        delays = (1, 2, 5, 10, 20, 30)
        while not self._stopping.is_set():
            superseded = False
            headers = self.config.signed_headers(
                method="GET", path=_SOCKET_PATH, body=""
            )
            # Explicitly negotiate the readiness frame. Older Hermes hosts
            # treat all text messages as encrypted frames and must not receive
            # this control message unexpectedly.
            headers["x-loopdy-capabilities"] = "socket-ready-v1"
            try:
                async with connect(
                    self.config.socket_url,
                    additional_headers=headers,
                    open_timeout=15,
                    close_timeout=5,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=MAX_ENCRYPTED_FRAME_CHARACTERS,
                    compression=None,
                ) as socket:
                    self._socket = socket
                    self._last_error = ""
                    ready = False
                    while not ready:
                        encoded = await asyncio.wait_for(
                            socket.recv(), timeout=self._readiness_timeout
                        )
                        if not isinstance(encoded, str):
                            raise ValueError("Loopdy Link requires text frames")
                        ready = await self.handle_wire_message(
                            encoded, callback, defer_callbacks=True
                        )
                    self._reconnect_attempt = 0
                    self._connected.set()
                    self._record_runtime_status("connected")
                    self._notify_status("connected")
                    pending = self._transport_get("pending_frame")
                    if isinstance(pending, dict):
                        await self._send_wire(pending)
                    async for encoded in socket:
                        if not isinstance(encoded, str):
                            raise ValueError("Loopdy Link requires text frames")
                        await self.handle_wire_message(
                            encoded, callback, defer_callbacks=True
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if _connection_was_replaced(exc):
                    superseded = True
                    self._superseded = True
                    self._last_error = "connection replaced by newer runtime"
                    logger.info("Loopdy Link connection superseded by newer runtime")
                else:
                    self._last_error = _connection_error_detail(exc)
                    logger.warning("Loopdy Link connection interrupted (%s)", self._last_error)
            finally:
                self._connected.clear()
                self._socket = None
                self._notify_status("disconnected", self._last_error)
                await self._stop_inbound_callback_dispatcher()
            if self._stopping.is_set() or superseded:
                self._record_runtime_status(
                    "superseded" if superseded else "disconnected",
                    self._last_error,
                )
                break
            delay = delays[min(self._reconnect_attempt, len(delays) - 1)]
            self._reconnect_attempt += 1
            self._record_runtime_status("reconnecting", self._last_error)
            self._notify_status("reconnecting", self._last_error)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    def _record_runtime_status(self, state: str, detail: str = "") -> None:
        """Publish redacted connection state through Hermes' durable plugin state."""
        try:
            previous = self.state.get("link.runtime_status", {})
            prior = previous if isinstance(previous, dict) else {}
            observed_at = int(time.time())
            last_connected_at = prior.get("last_connected_at")
            if state == "connected" and prior.get("state") != "connected":
                last_connected_at = observed_at
            value = {
                "state": state,
                "observed_at": observed_at,
                "last_connected_at": last_connected_at,
                "base_url": self.config.base_url,
                "device_id": self.config.device_id,
                "authorization_epoch": self.config.authorization_epoch,
                "reconnect_attempt": self._reconnect_attempt,
                "detail": " ".join(str(detail).split())[:160],
            }
            self.state.set("link.runtime_status", value)
        except Exception as exc:
            logger.warning(
                "Loopdy Link could not persist runtime status (%s)",
                _connection_error_detail(exc),
            )

    def _notify_status(self, state: str, detail: str = "") -> None:
        callback = self._status_callback
        if callback is None:
            return
        try:
            result = callback(state, detail)
            if inspect.isawaitable(result):
                logger.warning(
                    "Loopdy Link status callback must be synchronous; ignoring awaitable"
                )
        except Exception as exc:
            logger.warning(
                "Loopdy Link status callback failed (%s)",
                _connection_error_detail(exc),
            )

    async def _send_wire(self, value: dict[str, Any]) -> None:
        socket = self._socket
        if socket is None:
            raise ConnectionError("Loopdy Link is disconnected")
        await socket.send(json.dumps(value, separators=(",", ":"), sort_keys=True))

    async def _send_receipt(self, frame: EncryptedFrame) -> None:
        socket = self._socket
        if socket is None:
            return
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "receipt",
                    "deviceId": self.config.device_id,
                    "frameId": frame.frame_id,
                    "sourceDeviceId": frame.sender_device_id,
                    "sequence": frame.sequence,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    def _enqueue_inbound_callback(
        self,
        callback: Callable[[Any], Any],
        frame: EncryptedFrame,
        inbound: Any,
    ) -> None:
        self._inbound_callback_queue.put_nowait((callback, frame, inbound))
        if self._inbound_callback_task is None or self._inbound_callback_task.done():
            self._inbound_callback_task = asyncio.create_task(
                self._dispatch_inbound_callbacks(),
                name="loopdy-link-inbound-callbacks",
            )

    async def _stop_inbound_callback_dispatcher(self) -> None:
        task, self._inbound_callback_task = self._inbound_callback_task, None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        while not self._inbound_callback_queue.empty():
            try:
                self._inbound_callback_queue.get_nowait()
                self._inbound_callback_queue.task_done()
            except asyncio.QueueEmpty:
                break

    async def _dispatch_inbound_callbacks(self) -> None:
        while True:
            callback, frame, inbound = await self._inbound_callback_queue.get()
            try:
                sequences = self._transport_get("received_sequences", {})
                sequence_map = dict(sequences) if isinstance(sequences, dict) else {}
                has_previous = frame.sender_device_id in sequence_map
                previous = int(sequence_map.get(frame.sender_device_id, 0) or 0)
                if has_previous and frame.sequence <= previous:
                    await self._send_receipt(frame)
                    continue
                if has_previous and frame.sequence != previous + 1:
                    raise ValueError("Loopdy Link inbound sequence is invalid")
                if isinstance(inbound, _InboundLinkTurnFailure):
                    try:
                        await self._send_user_message_result(
                            inbound.message,
                            status="failed",
                            code=inbound.code,
                            message=inbound.detail,
                        )
                        await self._accept_inbound_frame(frame)
                    except Exception as delivery_error:
                        logger.warning(
                            "Loopdy Link could not deliver the correlated inbound failure (%s)",
                            _connection_error_detail(delivery_error),
                        )
                        await self._close_for_reconnect(
                            "correlated inbound failure delivery failed"
                        )
                        return
                    continue
                callback_error: Exception | None = None
                if inbound is not None:
                    try:
                        result = callback(inbound)
                        if inspect.isawaitable(result):
                            await result
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        callback_error = exc
                if callback_error is not None:
                    if isinstance(inbound, InboundLinkRelayReady):
                        detail = _connection_error_detail(callback_error)
                        logger.warning(
                            "Loopdy Link relay.ready callback failed; reconnecting (%s)",
                            detail,
                        )
                        self._last_error = detail
                        self._connected.clear()
                        self._record_runtime_status("unready", detail)
                        self._notify_status("unready", detail)
                        socket = self._socket
                        if socket is not None:
                            try:
                                await socket.close(
                                    code=1011,
                                    reason="relay enrollment failed",
                                )
                            except Exception:
                                pass
                        return
                    if isinstance(inbound, InboundLinkTurn):
                        logger.warning(
                            "Loopdy Link inbound user message failed (%s)",
                            _connection_error_detail(callback_error),
                        )
                        try:
                            await self._send_user_message_result(
                                inbound.message,
                                status="failed",
                                code="hermes_request_failed",
                                message="Hermes could not accept this message.",
                            )
                            await self._accept_inbound_frame(frame)
                        except Exception as delivery_error:
                            logger.warning(
                                "Loopdy Link could not deliver the correlated request failure (%s)",
                                _connection_error_detail(delivery_error),
                            )
                            await self._close_for_reconnect(
                                "correlated request failure delivery failed"
                            )
                            return
                        continue
                    logger.warning(
                        "Loopdy Link inbound callback failed; quarantining request (%s)",
                        _connection_error_detail(callback_error),
                    )
                    await self._accept_inbound_frame(frame)
                    continue
                if isinstance(inbound, InboundLinkTurn):
                    await self._send_user_message_result(
                        inbound.message, status="accepted"
                    )
                sequence_map[frame.sender_device_id] = frame.sequence
                self._transport_set("received_sequences", sequence_map)
                self._transport_set(
                    "last_received_sequence",
                    max(
                        int(self._transport_get("last_received_sequence", 0) or 0),
                        frame.sequence,
                    ),
                )
                await self._send_receipt(frame)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "Loopdy Link inbound transport or protocol handling failed; reconnecting (%s)",
                    _connection_error_detail(exc),
                )
                await self._close_for_reconnect(
                    "inbound transport or protocol handling failed"
                )
                return
            finally:
                self._inbound_callback_queue.task_done()

    async def _send_user_message_result(
        self,
        request: UserMessage,
        *,
        status: str,
        code: str | None = None,
        message: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "version": 1,
            "type": "user.message.result",
            "requestId": request.message_id,
            "sessionId": request.session_id,
            "agentId": request.agent_id,
            "status": status,
            "sentAt": int(time.time()),
        }
        if status == "failed":
            payload["code"] = code or "hermes_request_failed"
            payload["message"] = message or "Hermes could not accept this message."
        await self.send_payload(payload)

    async def _mark_failed_outbound_and_reconnect(self, frame: EncryptedFrame) -> None:
        pending = self._transport_get("pending_frame")
        if (
            not isinstance(pending, dict)
            or pending.get("id") != frame.frame_id
            or pending.get("sequence") != frame.sequence
        ):
            return
        self._transport_set("failed_pending_frame_id", frame.frame_id)
        await self._close_for_reconnect("outbound acknowledgement timed out")

    async def _close_for_reconnect(self, detail: str) -> None:
        self._last_error = detail
        self._connected.clear()
        socket = self._socket
        if socket is not None:
            try:
                await socket.close(code=1011, reason="Link delivery recovery")
            except Exception:
                pass

    async def _quarantine_inbound_payload(
        self,
        frame: EncryptedFrame,
        error: BaseException,
    ) -> None:
        # This is an authenticated, sequence-valid application payload. If its
        # bounded attachment processing fails, replaying the same durable frame
        # on every replacement socket can never repair it and instead creates a
        # permanent reconnect loop. Consume only that frame so later requests
        # remain usable; transport/protocol failures still escape normally.
        logger.warning(
            "Loopdy Link quarantined inbound payload (%s)",
            _connection_error_detail(error),
        )
        await self._accept_inbound_frame(frame)

    async def _accept_inbound_frame(self, frame: EncryptedFrame) -> None:
        sequences = self._transport_get("received_sequences", {})
        sequence_map = dict(sequences) if isinstance(sequences, dict) else {}
        has_previous = frame.sender_device_id in sequence_map
        previous = int(sequence_map.get(frame.sender_device_id, 0) or 0)
        if has_previous and frame.sequence <= previous:
            await self._send_receipt(frame)
            return
        if has_previous and frame.sequence != previous + 1:
            raise ValueError("Loopdy Link inbound sequence is invalid")
        sequence_map[frame.sender_device_id] = frame.sequence
        self._transport_set("received_sequences", sequence_map)
        self._transport_set(
            "last_received_sequence",
            max(
                int(self._transport_get("last_received_sequence", 0) or 0),
                frame.sequence,
            ),
        )
        await self._send_receipt(frame)

    async def _wait_for_prior_pending(self) -> None:
        deadline = asyncio.get_running_loop().time() + 20.0
        while isinstance(self._transport_get("pending_frame"), dict):
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Loopdy Link is waiting for relay acknowledgement")
            await asyncio.sleep(0.05)

    def _accept_outbound(self, value: dict[str, Any]) -> None:
        frame_id = value.get("id")
        sequence = value.get("sequence")
        if not isinstance(frame_id, str) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError("Loopdy Link acknowledgement is invalid")
        pending = self._transport_get("pending_frame")
        if not isinstance(pending, dict):
            return
        if pending.get("id") != frame_id or pending.get("sequence") != sequence:
            raise ValueError("Loopdy Link acknowledgement does not match pending state")
        self._transport_set("outbound_sequence", sequence)
        self._transport_set("pending_frame", None)
        if self._transport_get("failed_pending_frame_id") == frame_id:
            self._transport_set("failed_pending_frame_id", None)
        future = self._accepted.pop(frame_id, None)
        if future is not None and not future.done():
            future.set_result(None)

    def _reconcile_socket_ready(self, value: dict[str, Any]) -> None:
        expected = {
            "version",
            "type",
            "deviceId",
            "authorizationEpoch",
            "lastInboundSequence",
            "lastInboundFrameId",
            "lastAcknowledgedSequence",
        }
        if set(value) != expected or value.get("version") != 1 or value.get("type") != "socket.ready":
            raise ValueError("Loopdy Link socket readiness is invalid")
        if value.get("deviceId") != self.config.device_id:
            raise ValueError("Loopdy Link socket readiness device is invalid")
        if value.get("authorizationEpoch") != self.config.authorization_epoch:
            raise ValueError("Loopdy Link socket readiness epoch is invalid")
        server_sequence = value.get("lastInboundSequence")
        server_ack = value.get("lastAcknowledgedSequence")
        server_frame_id = value.get("lastInboundFrameId")
        if (
            not isinstance(server_sequence, int)
            or isinstance(server_sequence, bool)
            or server_sequence < 0
            or not isinstance(server_ack, int)
            or isinstance(server_ack, bool)
            or server_ack < 0
            or (
                server_frame_id is not None
                and (
                    not isinstance(server_frame_id, str)
                    or not 16 <= len(server_frame_id) <= 128
                    or any(
                        not (character.isalnum() or character in "_-")
                        for character in server_frame_id
                    )
                )
            )
            or (server_sequence == 0 and server_frame_id is not None)
        ):
            raise ValueError("Loopdy Link socket readiness state is invalid")

        state = self._transport_get("pending_frame")
        outbound = int(self._transport_get("outbound_sequence", 0) or 0)
        received = int(self._transport_get("last_received_sequence", 0) or 0)
        if not isinstance(state, dict):
            self._transport_set("outbound_sequence", max(outbound, server_sequence))
            self._transport_set("last_received_sequence", max(received, server_ack))
            return

        pending = parse_encrypted_frame(json.dumps(state, separators=(",", ":")))
        if (
            pending.sender_device_id != self.config.device_id
            or pending.sender_epoch != self.config.authorization_epoch
        ):
            raise ValueError("Loopdy Link pending frame owner is invalid")
        if pending.sequence == server_sequence and pending.frame_id == server_frame_id:
            self._transport_set("outbound_sequence", max(outbound, server_sequence))
            self._transport_set("last_received_sequence", max(received, server_ack))
            self._transport_set("pending_frame", None)
            if self._transport_get("failed_pending_frame_id") == pending.frame_id:
                self._transport_set("failed_pending_frame_id", None)
            future = self._accepted.pop(pending.frame_id, None)
            if future is not None and not future.done():
                future.set_result(None)
            return
        if self._transport_get("failed_pending_frame_id") == pending.frame_id:
            self._transport_set("outbound_sequence", server_sequence)
            self._transport_set("last_received_sequence", max(received, server_ack))
            self._transport_set("pending_frame", None)
            self._transport_set("failed_pending_frame_id", None)
            future = self._accepted.pop(pending.frame_id, None)
            if future is not None and not future.done():
                future.set_exception(TimeoutError("Loopdy Link delivery failed"))
            return
        self._transport_set("outbound_sequence", max(outbound, server_sequence))
        self._transport_set("last_received_sequence", max(received, server_ack))
        if pending.sequence == server_sequence + 1:
            # The relay is exactly one frame behind this durable pending send;
            # retain the byte-identical frame so retry remains idempotent.
            return

        rebased = EncryptedFrame(
            frame_id="frame_" + encode_base64url(os.urandom(18)),
            sender_device_id=self.config.device_id,
            sender_epoch=self.config.authorization_epoch,
            sequence=server_sequence + 1,
            ack=max(pending.ack, server_ack),
            ciphertext=self.cipher.seal(self.cipher.open(pending.ciphertext)),
        )
        self._transport_set("pending_frame", rebased.wire_value())
        future = self._accepted.pop(pending.frame_id, None)
        if future is not None:
            self._accepted[rebased.frame_id] = future

    def _accept_live_activity(self, value: dict[str, Any]) -> None:
        update_id = value.get("updateId")
        count = value.get("activityCount")
        if (
            not isinstance(update_id, str)
            or not 16 <= len(update_id) <= 128
            or any(not (character.isalnum() or character in "_-") for character in update_id)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= 32
            or set(value) != {"version", "type", "updateId", "activityCount"}
        ):
            raise ValueError("Loopdy Link Live Activity acknowledgement is invalid")
        future = self._live_activity_accepted.get(update_id)
        if future is not None and not future.done():
            future.set_result(None)

    def _transport_key(self, suffix: str) -> str:
        return f"{self._transport_state_prefix}.{suffix}"

    def _transport_get(self, suffix: str, default: Any = None) -> Any:
        return self.state.get(self._transport_key(suffix), default)

    def _transport_set(self, suffix: str, value: Any) -> None:
        self.state.set(self._transport_key(suffix), value)

    def _migrate_legacy_transport_state(self) -> None:
        """Move pre-device-scoped counters only when their owner is unambiguous."""
        runtime = self.state.get("link.runtime_status", {})
        runtime_device_id = runtime.get("device_id") if isinstance(runtime, dict) else None
        if runtime_device_id != self.config.device_id:
            return
        missing = object()
        for suffix in self._TRANSPORT_STATE_SUFFIXES:
            scoped_key = self._transport_key(suffix)
            if self.state.get(scoped_key, missing) is not missing:
                continue
            legacy = self.state.get(f"link.{suffix}", missing)
            if legacy is not missing:
                self.state.set(scoped_key, legacy)


def load_runtime_config(values: Mapping[str, str] | None = None) -> LinkRuntimeConfig | None:
    source = os.environ if values is None else values
    keys = (
        "LOOPDY_LINK_BASE_URL",
        "LOOPDY_LINK_DEVICE_ID",
        "LOOPDY_LINK_AUTHORIZATION_EPOCH",
        "LOOPDY_LINK_SIGNING_PRIVATE_KEY",
        "LOOPDY_LINK_ACCOUNT_KEY",
    )
    if not any(str(source.get(key) or "").strip() for key in keys):
        return None
    return LinkRuntimeConfig.from_mapping(source)


def _connection_error_detail(error: BaseException) -> str:
    message = " ".join(str(error).split())
    detail = type(error).__name__
    if message:
        detail += f": {message}"
    return detail[:160]


def _connection_was_replaced(error: BaseException) -> bool:
    """Recognize the relay's private single-owner close without string matching."""
    pending: list[Any] = [error]
    seen: set[int] = set()
    while pending:
        candidate = pending.pop()
        identity = id(candidate)
        if identity in seen:
            continue
        seen.add(identity)
        if getattr(candidate, "code", None) == 4_000:
            return True
        for name in ("rcvd", "sent", "__cause__", "__context__"):
            nested = getattr(candidate, name, None)
            if nested is not None:
                pending.append(nested)
    return False


def _validated_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Loopdy Link base URL must be an HTTPS origin")
    return f"https://{parsed.netloc}"


def _opaque(value: str, minimum: int, maximum: int) -> str:
    if (
        len(value) < minimum
        or len(value) > maximum
        or any(not (character.isalnum() or character in "_-") for character in value)
    ):
        raise ValueError("Loopdy Link coordinate is invalid")
    return value


def _validated_live_activity_update(payload: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "version",
        "type",
        "updateId",
        "sessionReference",
        "phase",
        "currentAction",
        "progress",
        "completedSteps",
        "activeSubagentCount",
        "latestTool",
        "timestamp",
        "expires",
    }
    phases = {
        "thinking",
        "waiting",
        "using_tool",
        "delegating",
        "responding",
        "completed",
        "failed",
    }
    update_id = payload.get("updateId")
    session_reference = payload.get("sessionReference")
    current_action = payload.get("currentAction")
    latest_tool = payload.get("latestTool")
    timestamp = payload.get("timestamp")
    expires = payload.get("expires")
    valid = (
        set(payload) == expected
        and payload.get("version") == 1
        and payload.get("type") == "live_activity.update"
        and isinstance(update_id, str)
        and 16 <= len(update_id) <= 128
        and all(character.isalnum() or character in "_-" for character in update_id)
        and isinstance(session_reference, str)
        and len(session_reference) == 43
        and all(character.isalnum() or character in "_-" for character in session_reference)
        and payload.get("phase") in phases
        and _useful_live_text(current_action, 96)
        and _bounded_live_integer(payload.get("progress"), 0, 100)
        and _bounded_live_integer(payload.get("completedSteps"), 0, 999)
        and _bounded_live_integer(payload.get("activeSubagentCount"), 0, 99)
        and (latest_tool is None or _useful_live_text(latest_tool, 64))
        and _bounded_live_integer(timestamp, 1, 9_999_999_999)
        and _bounded_live_integer(expires, 1, 9_999_999_999)
        and int(expires) > int(timestamp)
        and int(expires) - int(timestamp) <= 120
    )
    if not valid:
        raise ValueError("Loopdy Link Live Activity update is invalid")
    return dict(payload)


def _useful_live_text(value: Any, maximum: int) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _bounded_live_integer(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


__all__ = [
    "InboundLinkCommandCatalog",
    "InboundLinkGenerativeUIFormSubmission",
    "InboundLinkWorkspaceRequest",
    "InboundLinkPersonalityRequest",
    "InboundLinkRelayReady",
    "InboundLinkSessionFork",
    "InboundLinkTurn",
    "LinkRuntimeConfig",
    "LoopdyLinkClient",
    "canonical_device_request",
    "load_runtime_config",
]
