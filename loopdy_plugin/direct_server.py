"""Bounded loopback WebSocket transport for authenticated direct requests.

This module owns transport, authentication, admission, and exact-connection
delivery. Application command semantics and authoritative session reads remain
with callbacks supplied by the runtime adapter.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Awaitable, Callable

import websockets
from websockets.asyncio.server import Server, ServerConnection
from websockets.exceptions import ConnectionClosed

from .direct_connection import DirectPeer
from .link_contracts import parse_workspace_request
from .session_stream import (
    SessionStreamSubscription,
    StreamClosed,
    StreamResetRequired,
)


_ROUTE = "/loopdy/direct/v1"
_MAX_WIRE_BYTES = 512 * 1024
_MAX_JSON_DEPTH = 20
_MAX_CONNECTIONS = 16
_MAX_AUTHENTICATED_PER_PEER = 2
_MAX_COMMANDS = 8
_MAX_SUBSCRIPTIONS_PER_CONNECTION = 4
_MAX_SESSION_SETUPS = 4
_AUTHENTICATION_TIMEOUT = 10.0
_SEND_TIMEOUT = 5.0
_SNAPSHOT_TIMEOUT = 15.0
_OPAQUE = re.compile(r"^[A-Za-z0-9_-]+$")
_COMMAND_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_QUERY_OPERATIONS = frozenset(
    {
        "sessions.state",
        "sessions.content",
        "sessions.list",
        "agents.list",
        "dashboard.load",
        "scheduled_tasks.list",
        "scheduled_tasks.delivery_targets",
        "agent_defaults.get",
        "voice_settings.get",
        "skills_tools.list",
        "skills_tools.get",
        "projects.list",
        "projects.git.capabilities",
        "projects.git.status",
        "projects.git.diff",
        "approvals.load",
        "host_runtime.status",
        "plugin_update.status",
    }
)


Dispatch = Callable[["DirectRequestContext", dict[str, Any]], Awaitable[dict[str, Any]]]
OpenSession = Callable[
    ["DirectRequestContext", str, str], Awaitable["DirectSessionView"]
]


@dataclass(frozen=True)
class DirectSessionView:
    """Canonical snapshot plus the already-open transient feed that follows it."""

    snapshot: dict[str, Any]
    subscription: SessionStreamSubscription
    process_epoch: str
    start_cursor: int


@dataclass(frozen=True)
class DirectRequestContext:
    """Immutable authenticated ownership for one exact socket connection."""

    peer: DirectPeer
    connection_id: str
    _server: "DirectServer" = field(repr=False, compare=False)

    async def send(self, payload: dict[str, Any]) -> None:
        """Deliver to this request's original live authenticated connection."""

        await self._server._send_from_context(self, payload)


@dataclass(eq=False)
class _Connection:
    websocket: ServerConnection
    connection_id: str
    peer: DirectPeer | None = None
    authenticated_key: tuple[str, int] | None = None
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    subscriptions: dict[str, "_Subscription"] = field(default_factory=dict)


@dataclass(eq=False)
class _Subscription:
    subscription_id: str
    task: asyncio.Task[None] | None = None
    feed: SessionStreamSubscription | None = None


def _quiet_logger() -> logging.Logger:
    logger = logging.getLogger("loopdy_plugin.direct_server")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    logger.propagate = False
    logger.setLevel(logging.CRITICAL)
    return logger


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _check_depth(value: Any) -> None:
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting is too deep")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)


def _decode_message(raw: str | bytes) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise ValueError("binary messages are unsupported")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("message is not valid UTF-8") from error
    if len(encoded) > _MAX_WIRE_BYTES:
        raise ValueError("message is too large")
    try:
        value = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise ValueError("message is not strict JSON") from error
    if type(value) is not dict:
        raise ValueError("message must be an object")
    _check_depth(value)
    if type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("message version is invalid")
    if not isinstance(value.get("type"), str):
        raise ValueError("message type is invalid")
    return value


def _encode_message(payload: dict[str, Any]) -> str:
    if type(payload) is not dict:
        raise ValueError("outbound payload must be an object")
    _check_depth(payload)
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("outbound payload is not strict JSON") from error
    if len(encoded) > _MAX_WIRE_BYTES:
        raise ValueError("outbound payload is too large")
    return encoded.decode("utf-8")


def _opaque(value: Any, name: str, *, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or _OPAQUE.fullmatch(value) is None
    ):
        raise ValueError(f"{name} is invalid")
    return value


class DirectServer:
    """One in-process, loopback-only direct transport listener."""

    def __init__(
        self,
        authority: Any,
        journal: Any,
        dispatch: Dispatch,
        open_session: OpenSession | None = None,
    ) -> None:
        if not callable(dispatch):
            raise ValueError("dispatch must be callable")
        if open_session is not None and not callable(open_session):
            raise ValueError("open_session must be callable")
        self._authority = authority
        self._journal = journal
        self._dispatch = dispatch
        self._open_session = open_session
        self._server: Server | None = None
        self._connections: dict[str, _Connection] = {}
        self._authenticated_counts: dict[tuple[str, int], int] = {}
        self._request_tasks: set[asyncio.Task[None]] = set()
        self._session_tasks: set[asyncio.Task[None]] = set()
        self._stopping = False

    @property
    def port(self) -> int:
        server = self._server
        if server is None or not server.sockets:
            raise RuntimeError("direct server is not running")
        return int(server.sockets[0].getsockname()[1])

    async def start(self, port: int = 0) -> None:
        if self._server is not None:
            raise RuntimeError("direct server is already running")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("port is invalid")
        self._stopping = False
        self._server = await websockets.serve(
            self._handle_connection,
            "127.0.0.1",
            port,
            process_request=self._process_request,
            origins=[None],
            compression=None,
            open_timeout=_AUTHENTICATION_TIMEOUT,
            close_timeout=2,
            max_size=_MAX_WIRE_BYTES,
            max_queue=8,
            write_limit=32 * 1024,
            ping_interval=20,
            ping_timeout=5,
            server_header=None,
            logger=_quiet_logger(),
        )

    async def stop(self) -> None:
        server = self._server
        if server is None:
            return
        self._stopping = True
        self._server = None
        server.close()
        connections = tuple(self._connections.values())
        await asyncio.gather(
            *(self._close(connection, 1001) for connection in connections),
            return_exceptions=True,
        )
        try:
            await asyncio.wait_for(server.wait_closed(), 5)
        except asyncio.TimeoutError:
            pass
        if self._request_tasks:
            _, pending = await asyncio.wait(tuple(self._request_tasks), timeout=5)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    async def _process_request(self, connection: ServerConnection, request: Any):
        origins = request.headers.get_all("Origin")
        if request.path != _ROUTE:
            return connection.respond(HTTPStatus.NOT_FOUND, "Not Found\n")
        if origins:
            return connection.respond(HTTPStatus.FORBIDDEN, "Forbidden\n")
        return None

    async def _handle_connection(self, websocket: ServerConnection) -> None:
        if self._stopping or len(self._connections) >= _MAX_CONNECTIONS:
            await self._close_socket(websocket, 1013)
            return
        connection = _Connection(websocket=websocket, connection_id=secrets.token_urlsafe(32))
        self._connections[connection.connection_id] = connection
        watchdog: asyncio.Task[None] | None = None
        try:
            await asyncio.wait_for(
                self._authenticate(connection), timeout=_AUTHENTICATION_TIMEOUT
            )
            watchdog = asyncio.create_task(self._watchdog(connection))
            async for raw in websocket:
                await self._handle_authenticated_message(connection, raw)
        except asyncio.CancelledError:
            raise
        except (ConnectionClosed, asyncio.TimeoutError, ValueError, TypeError):
            pass
        except Exception:
            pass
        finally:
            if watchdog is not None:
                watchdog.cancel()
                await asyncio.gather(watchdog, return_exceptions=True)
            await self._cleanup_connection(connection)

    async def _authenticate(self, connection: _Connection) -> None:
        hello = _decode_message(await connection.websocket.recv())
        if set(hello) != {
            "version",
            "type",
            "deviceId",
            "authorizationEpoch",
            "clientNonce",
        } or hello["type"] != "direct.hello":
            raise ValueError("invalid hello")
        device_id = _opaque(hello["deviceId"], "deviceId", minimum=1, maximum=96)
        epoch = hello["authorizationEpoch"]
        if type(epoch) is not int or epoch <= 0:
            raise ValueError("authorizationEpoch is invalid")
        client_nonce = _opaque(
            hello["clientNonce"], "clientNonce", minimum=43, maximum=43
        )
        challenge = self._authority.issue_challenge(
            peer_device_id=device_id,
            peer_epoch=epoch,
            connection_id=connection.connection_id,
            client_nonce=client_nonce,
        )
        await self._send(
            connection,
            {"version": 1, "type": "direct.challenge", "challenge": challenge},
            private=False,
        )
        proof = _decode_message(await connection.websocket.recv())
        if set(proof) != {"version", "type", "nonce", "peerProof"} or proof[
            "type"
        ] != "direct.proof":
            raise ValueError("invalid proof")
        peer = self._authority.verify_challenge_response(
            peer_device_id=device_id,
            peer_epoch=epoch,
            connection_id=connection.connection_id,
            nonce=proof["nonce"],
            peer_proof=proof["peerProof"],
        )
        key = (peer.peer_device_id, peer.peer_epoch)
        if self._authenticated_counts.get(key, 0) >= _MAX_AUTHENTICATED_PER_PEER:
            raise ValueError("authenticated peer capacity")
        connection.peer = peer
        connection.authenticated_key = key
        self._authenticated_counts[key] = self._authenticated_counts.get(key, 0) + 1
        await self._send(
            connection,
            {
                "version": 1,
                "type": "direct.ready",
                "connectionID": connection.connection_id,
            },
            private=True,
        )

    async def _watchdog(self, connection: _Connection) -> None:
        while True:
            await asyncio.sleep(1)
            peer = connection.peer
            if peer is None:
                return
            try:
                self._authority.validate_peer(peer)
            except Exception:
                await self._close(connection, 1008)
                return

    async def _handle_authenticated_message(
        self, connection: _Connection, raw: str | bytes
    ) -> None:
        message = _decode_message(raw)
        message_type = message["type"]
        if message_type == "direct.command":
            await self._admit_command_message(connection, message)
        elif message_type == "direct.query":
            await self._admit_query_message(connection, message)
        elif message_type == "session.subscribe":
            await self._subscribe(connection, message)
        elif message_type == "session.unsubscribe":
            await self._unsubscribe(connection, message)
        else:
            raise ValueError("unknown message type")

    async def _admit_command_message(
        self, connection: _Connection, message: dict[str, Any]
    ) -> None:
        command_id = message.get("commandID")
        valid_id = isinstance(command_id, str) and _COMMAND_ID.fullmatch(command_id)
        try:
            if set(message) != {
                "version",
                "type",
                "commandID",
                "issuedAt",
                "payload",
            }:
                raise ValueError("command fields are invalid")
            if not valid_id:
                raise ValueError("commandID is invalid")
            if type(message["issuedAt"]) is not int:
                raise ValueError("issuedAt is invalid")
            if type(message["payload"]) is not dict:
                raise ValueError("payload is invalid")
            _encode_message(message["payload"])
            peer = self._require_peer(connection)
            self._authority.validate_peer(peer)
        except Exception:
            if valid_id:
                await self._send_rejected(connection, command_id, "invalid")
                return
            raise ValueError("invalid command")
        if len(self._request_tasks) >= _MAX_COMMANDS:
            await self._send_rejected(connection, command_id, "capacity")
            return
        context = DirectRequestContext(peer, connection.connection_id, self)
        task = asyncio.create_task(
            self._run_command(
                connection,
                context,
                command_id,
                message["issuedAt"],
                message["payload"],
            )
        )
        self._request_tasks.add(task)
        task.add_done_callback(self._request_tasks.discard)

    async def _admit_query_message(
        self, connection: _Connection, message: dict[str, Any]
    ) -> None:
        request_id = message.get("requestID")
        valid_id = (
            isinstance(request_id, str)
            and 16 <= len(request_id) <= 128
            and _OPAQUE.fullmatch(request_id) is not None
        )
        try:
            if set(message) != {"version", "type", "requestID", "payload"}:
                raise ValueError("query fields are invalid")
            if not valid_id or type(message["payload"]) is not dict:
                raise ValueError("query is invalid")
            request = parse_workspace_request(message["payload"])
            if request.operation not in _QUERY_OPERATIONS:
                raise ValueError("query operation is not read-only")
            peer = self._require_peer(connection)
            self._authority.validate_peer(peer)
        except Exception:
            if valid_id:
                await self._send_query_failure(connection, request_id, "invalid")
                return
            raise ValueError("invalid query")
        if len(self._request_tasks) >= _MAX_COMMANDS:
            await self._send_query_failure(connection, request_id, "capacity")
            return
        context = DirectRequestContext(peer, connection.connection_id, self)
        task = asyncio.create_task(
            self._run_query(connection, context, request_id, message["payload"])
        )
        self._request_tasks.add(task)
        task.add_done_callback(self._request_tasks.discard)

    async def _run_query(
        self,
        connection: _Connection,
        context: DirectRequestContext,
        request_id: str,
        payload: dict[str, Any],
    ) -> None:
        try:
            self._authority.validate_peer(context.peer)
            result = await self._dispatch(context, payload)
            response = {
                "version": 1,
                "type": "direct.query.result",
                "requestID": request_id,
                "result": result,
            }
            _encode_message(response)
        except asyncio.CancelledError:
            raise
        except Exception:
            response = {
                "version": 1,
                "type": "direct.query.result",
                "requestID": request_id,
                "result": {"status": "failed", "code": "query_failed"},
            }
        try:
            await self._send(connection, response, private=True)
        except Exception:
            pass

    async def _send_query_failure(
        self, connection: _Connection, request_id: str, code: str
    ) -> None:
        await self._send(
            connection,
            {
                "version": 1,
                "type": "direct.query.result",
                "requestID": request_id,
                "result": {"status": "failed", "code": code},
            },
            private=True,
        )

    async def _run_command(
        self,
        connection: _Connection,
        context: DirectRequestContext,
        command_id: str,
        issued_at: int,
        payload: dict[str, Any],
    ) -> None:
        admission = None
        current = None
        try:
            self._authority.validate_peer(context.peer)
            admission = await self._journal.admit(
                context.peer, command_id, issued_at, payload
            )
            current = admission
            if admission.is_new:
                result = await self._dispatch(context, payload)
                _encode_message(
                    {
                        "version": 1,
                        "type": "direct.receipt",
                        "commandID": command_id,
                        "state": "completed",
                        "result": result,
                    }
                )
                current = await self._journal.complete(admission, result)
        except asyncio.CancelledError:
            raise
        except Exception:
            if admission is None:
                try:
                    await self._send_rejected(connection, command_id, "invalid")
                except Exception:
                    pass
                return
            if admission.is_new:
                try:
                    current = await self._journal.complete(
                        admission, {"accepted": False, "code": "uncertain"}
                    )
                except Exception:
                    current = admission
        if current is None:
            return
        receipt: dict[str, Any] = {
            "version": 1,
            "type": "direct.receipt",
            "commandID": command_id,
            "state": current.state,
        }
        if current.result is not None:
            receipt["result"] = current.result
        try:
            await self._send(connection, receipt, private=True)
        except Exception:
            pass

    async def _send_rejected(
        self, connection: _Connection, command_id: str, code: str
    ) -> None:
        await self._send(
            connection,
            {
                "version": 1,
                "type": "direct.rejected",
                "commandID": command_id,
                "code": code,
            },
            private=True,
        )

    async def _subscribe(
        self, connection: _Connection, message: dict[str, Any]
    ) -> None:
        if self._open_session is None or set(message) != {
            "version",
            "type",
            "subscriptionID",
            "agentId",
            "sessionId",
        }:
            raise ValueError("invalid subscription")
        subscription_id = _opaque(
            message["subscriptionID"], "subscriptionID", minimum=16, maximum=128
        )
        agent_id = _opaque(message["agentId"], "agentId", minimum=1, maximum=96)
        session_id = _opaque(
            message["sessionId"], "sessionId", minimum=1, maximum=180
        )
        peer = self._require_peer(connection)
        self._authority.validate_peer(peer)
        previous = connection.subscriptions.pop(subscription_id, None)
        if previous is not None:
            await self._cancel_subscription(previous)
        if len(connection.subscriptions) >= _MAX_SUBSCRIPTIONS_PER_CONNECTION:
            raise ValueError("subscription capacity")
        if len(self._session_tasks) >= _MAX_SESSION_SETUPS:
            raise ValueError("session setup capacity")
        owned = _Subscription(subscription_id)
        connection.subscriptions[subscription_id] = owned
        context = DirectRequestContext(peer, connection.connection_id, self)
        task = asyncio.create_task(
            self._run_subscription(
                connection, owned, context, agent_id=agent_id, session_id=session_id
            )
        )
        owned.task = task
        self._session_tasks.add(task)
        task.add_done_callback(self._session_tasks.discard)

    async def _unsubscribe(
        self, connection: _Connection, message: dict[str, Any]
    ) -> None:
        if set(message) != {"version", "type", "subscriptionID"}:
            raise ValueError("invalid unsubscribe")
        subscription_id = _opaque(
            message["subscriptionID"], "subscriptionID", minimum=16, maximum=128
        )
        self._authority.validate_peer(self._require_peer(connection))
        owned = connection.subscriptions.pop(subscription_id, None)
        if owned is not None:
            await self._cancel_subscription(owned)

    async def _run_subscription(
        self,
        connection: _Connection,
        owned: _Subscription,
        context: DirectRequestContext,
        *,
        agent_id: str,
        session_id: str,
    ) -> None:
        view: DirectSessionView | None = None
        try:
            assert self._open_session is not None
            view = await asyncio.wait_for(
                self._open_session(context, agent_id, session_id),
                timeout=_SNAPSHOT_TIMEOUT,
            )
            self._validate_session_view(view)
            owned.feed = view.subscription
            if connection.subscriptions.get(owned.subscription_id) is not owned:
                return
            await self._send(
                connection,
                {
                    "version": 1,
                    "type": "session.snapshot",
                    "subscriptionID": owned.subscription_id,
                    "processEpoch": view.process_epoch,
                    "cursor": view.start_cursor,
                    "payload": view.snapshot,
                },
                private=True,
            )
            while connection.subscriptions.get(owned.subscription_id) is owned:
                try:
                    event = await view.subscription.receive()
                except StreamResetRequired as reset:
                    await self._send(
                        connection,
                        {
                            "version": 1,
                            "type": "session.reset",
                            "subscriptionID": owned.subscription_id,
                            "processEpoch": reset.process_epoch,
                            "cursor": reset.cursor,
                            "code": "state_reset",
                        },
                        private=True,
                    )
                    return
                await self._send(
                    connection,
                    {
                        "version": 1,
                        "type": "session.event",
                        "subscriptionID": owned.subscription_id,
                        "processEpoch": event["processEpoch"],
                        "cursor": event["cursor"],
                        "payload": event["payload"],
                    },
                    private=True,
                )
        except asyncio.CancelledError:
            raise
        except (ConnectionClosed, ConnectionError, StreamClosed):
            pass
        except Exception:
            pass
        finally:
            if view is not None:
                view.subscription.close()
            if connection.subscriptions.get(owned.subscription_id) is owned:
                connection.subscriptions.pop(owned.subscription_id, None)

    def _validate_session_view(self, view: Any) -> None:
        if not isinstance(view, DirectSessionView):
            raise ValueError("open_session returned an invalid view")
        if type(view.snapshot) is not dict:
            raise ValueError("session snapshot is invalid")
        _encode_message(view.snapshot)
        _opaque(view.process_epoch, "processEpoch", minimum=1, maximum=128)
        if type(view.start_cursor) is not int or view.start_cursor < 0:
            raise ValueError("session start cursor is invalid")
        if not isinstance(view.subscription, SessionStreamSubscription):
            raise ValueError("session subscription is invalid")

    async def _send_from_context(
        self, context: DirectRequestContext, payload: dict[str, Any]
    ) -> None:
        connection = self._connections.get(context.connection_id)
        if connection is None or connection.peer != context.peer:
            raise ConnectionError("original direct connection is unavailable")
        await self._send(connection, payload, private=True)

    async def _send(
        self, connection: _Connection, payload: dict[str, Any], *, private: bool
    ) -> None:
        encoded = _encode_message(payload)
        try:
            async with connection.send_lock:
                if private:
                    peer = self._require_peer(connection)
                    self._authority.validate_peer(peer)
                    if self._connections.get(connection.connection_id) is not connection:
                        raise ConnectionError("direct connection is unavailable")
                await asyncio.wait_for(
                    connection.websocket.send(encoded), timeout=_SEND_TIMEOUT
                )
        except Exception as error:
            await self._close(connection, 1011)
            raise ConnectionError("direct connection send failed") from None

    def _require_peer(self, connection: _Connection) -> DirectPeer:
        if connection.peer is None:
            raise ValueError("direct connection is unauthenticated")
        return connection.peer

    async def _cancel_subscription(self, owned: _Subscription) -> None:
        if owned.feed is not None:
            owned.feed.close()
        if owned.task is not None and owned.task is not asyncio.current_task():
            owned.task.cancel()
            # Cancellation-resistant snapshot owners must not block replacement
            # or connection teardown. The ownership token below prevents a
            # stale completion from sending or removing its replacement.
            await asyncio.sleep(0)

    async def _cleanup_connection(self, connection: _Connection) -> None:
        if self._connections.get(connection.connection_id) is connection:
            self._connections.pop(connection.connection_id, None)
        owned_subscriptions = tuple(connection.subscriptions.values())
        connection.subscriptions.clear()
        await asyncio.gather(
            *(self._cancel_subscription(owned) for owned in owned_subscriptions),
            return_exceptions=True,
        )
        if connection.authenticated_key is not None:
            count = self._authenticated_counts.get(connection.authenticated_key, 0)
            if count <= 1:
                self._authenticated_counts.pop(connection.authenticated_key, None)
            else:
                self._authenticated_counts[connection.authenticated_key] = count - 1
            connection.authenticated_key = None
        await self._close_socket(connection.websocket, 1000)

    async def _close(self, connection: _Connection, code: int) -> None:
        await self._close_socket(connection.websocket, code)

    async def _close_socket(self, websocket: ServerConnection, code: int) -> None:
        try:
            await asyncio.wait_for(websocket.close(code=code), timeout=2)
        except Exception:
            pass


__all__ = ["DirectRequestContext", "DirectServer", "DirectSessionView"]
