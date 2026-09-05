"""Application service for local Loopdy devices and push providers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import queue
import random
import re
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .events import LoopdyEvent
from .link_contracts import ExpiredHostRelayEnrollment, RelayReady
from .presentation import shape_notification
from .provider import DeliveryError, LiveActivityState, PushProvider
from .providers.apns import ApnsPushProvider, load_apns_config
from .providers.expo import ExpoPushProvider
from .relay_client import (
    RelayClient,
    RelayConfig,
    RelayOutcomeUnknown,
    RelayPushProvider,
    delivery_coordinates,
    live_activity_delivery_coordinates,
    local_sender_key_set,
    normalize_relay_operation,
    validate_registration_response,
)
from .store import LoopdyStore
from .targets import validate_target


logger = logging.getLogger("hermes.plugins.loopdy")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_RELAY_REGISTRATION_SCOPE_FIELDS = (
    "version",
    "device_id",
    "provider",
    "recipient_public_key",
    "recipient_key_id",
    "push_token",
    "environment",
    "topic",
    "label",
    "groups",
)


class _ProviderLease:
    def __init__(self, service: "LoopdyService", provider: Any) -> None:
        self._service = service
        self.provider = provider
        self._released = False

    def __enter__(self) -> Any:
        return self.provider

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.release()

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._service._release_provider(self.provider)


class LoopdyService:
    def __init__(
        self,
        store: LoopdyStore,
        *,
        providers: Mapping[str, Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        jitter_fn: Callable[[], float] = random.random,
        now_fn: Callable[[], Any] = lambda: datetime.now().astimezone(),
        timestamp_fn: Callable[[], float] = time.time,
        max_attempts: int = 3,
        queue_size: int = 256,
    ):
        self.store = store
        self._providers = dict(providers or {})
        self._sleep = sleep_fn
        self._jitter = jitter_fn
        self._now = now_fn
        self._timestamp = timestamp_fn
        self._max_attempts = min(5, max(1, int(max_attempts)))
        self._queue: queue.Queue[tuple[LoopdyEvent, str] | None] = queue.Queue(
            maxsize=min(4096, max(1, int(queue_size)))
        )
        self._live_activity_queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=min(4096, max(1, int(queue_size)))
        )
        self._worker: threading.Thread | None = None
        self._live_activity_worker: threading.Thread | None = None
        self._worker_lock = threading.Lock()
        self._recovery_wakeup = threading.Event()
        self._recovery_timer_lock = threading.Lock()
        self._recovery_timer: threading.Timer | None = None
        self._recovery_timer_due = 0.0
        self._live_activity_worker_lock = threading.Lock()
        self._live_activity_lifecycle_lock = threading.Lock()
        self._provider_lock = threading.RLock()
        self._provider_inflight: dict[int, int] = {}
        self._provider_retired: set[int] = set()
        self._provider_close_events: dict[int, threading.Event] = {}
        self._provider_closed: set[int] = set()
        self._provider_identity: dict[int, Any] = {
            id(provider): provider for provider in self._providers.values()
        }
        self._closed = False
        self._closing = False
        if self.store.has_pending_live_activity_updates() or self.store.has_pending_relay_live_activity_updates():
            self._ensure_live_activity_worker()
        if self.store.has_pending_relay_operations():
            self._ensure_worker()
        if self.store.queued_relay_events(limit=1):
            self._resume_queued_relay_events()

    def health(self) -> dict[str, Any]:
        mode = self.store.provider_mode()
        try:
            self._provider(mode)
            configured = True
            configuration_error = ""
        except (ValueError, DeliveryError) as error:
            configured = False
            configuration_error = _safe_error(error)
        compatible_devices = len(self.store.resolve_devices("all", mode))
        ready = configured and compatible_devices > 0
        if not configured:
            detail = configuration_error
        elif compatible_devices == 0:
            detail = f"No {mode} Loopdy devices are registered"
        else:
            detail = f"{mode.capitalize()} provider ready"
        return {
            "mode": mode,
            "configured": configured,
            "ready": ready,
            "detail": detail,
            "compatible_devices": compatible_devices,
        }

    def adopt_link_relay_device(
        self,
        registration: RelayReady,
        *,
        sender_device_id: str,
    ) -> dict[str, Any]:
        """Mirror cloud-confirmed relay readiness from an authenticated Link device."""
        self._assert_open()
        if not isinstance(registration, RelayReady):
            raise ValueError("Loopdy Link relay readiness is invalid")
        if registration.scope != "host_relay":
            raise ValueError("Loopdy Link wake readiness cannot configure a host relay device")
        if registration.device_id != str(sender_device_id or ""):
            raise ValueError("Loopdy Link relay device does not match the verified sender")
        now = int(self._timestamp())
        if registration.lease_expires <= now:
            raise ExpiredHostRelayEnrollment("Loopdy Link host-relay enrollment has expired")
        if registration.sent_at > now + 300:
            raise ValueError("Loopdy Link relay readiness is from the future")

        acknowledged_ids = list(registration.acknowledged_sender_key_ids)
        with self._provider_lease("relay") as provider:
            sender_key_set_fn = getattr(provider, "sender_key_set", None)
            if not callable(sender_key_set_fn):
                sender_key_set_fn = getattr(getattr(provider, "client", None), "sender_key_set", None)
            selector = getattr(provider, "select_sender_key_id", None)
            if not callable(sender_key_set_fn) or not callable(selector):
                raise ValueError("Relay sender-key configuration is unavailable")
            sender_key_set = sender_key_set_fn()
            if (
                not isinstance(sender_key_set, dict)
                or sender_key_set.get("revision") != registration.sender_key_revision
            ):
                raise ValueError("Loopdy Link relay sender-key revision is invalid")
            configured_ids = {
                str(item.get("key_id"))
                for item in (sender_key_set.get("current"), sender_key_set.get("previous"))
                if isinstance(item, dict) and item.get("key_id")
            }
            if not set(acknowledged_ids).issubset(configured_ids):
                raise ValueError("Loopdy Link relay sender-key acknowledgement is invalid")
            selected_id = selector(acknowledged_ids)
            if selected_id not in acknowledged_ids:
                raise ValueError("Loopdy Link relay sender-key acknowledgement is invalid")

        existing = self.store.get_device(registration.device_id)
        if existing is not None and int(existing.get("revision") or 0) > registration.acknowledgement_revision:
            raise ValueError("Loopdy Link relay readiness revision is stale")

        def matches_registration(device: Mapping[str, Any]) -> bool:
            return (
                device.get("provider") == "relay"
                and not device.get("revoked")
                and device.get("recipient_public_key") == registration.recipient_public_key
                and device.get("recipient_key_id") == registration.recipient_key_id
                and int(device.get("lease_expires") or 0) == registration.lease_expires
                and device.get("token_environment") == registration.environment
                and device.get("label") == registration.device_name
            )

        if existing is not None and int(existing.get("revision") or 0) in {
            registration.enrollment_revision,
            registration.acknowledgement_revision,
        } and not matches_registration(existing):
            raise ValueError("Loopdy Link relay readiness conflicts with the local device")

        changed = False
        existing_revision = 0 if existing is None else int(existing.get("revision") or 0)
        if existing_revision < registration.enrollment_revision:
            result = self.store.register_relay_device(
                device_id=registration.device_id,
                recipient_public_key=registration.recipient_public_key,
                recipient_key_id=registration.recipient_key_id,
                revision=registration.enrollment_revision,
                lease_expires=registration.lease_expires,
                normalized_body=registration.wire_value(),
                token_environment=registration.environment,
                label=registration.device_name,
                now=now,
            )
            changed = bool(result.get("changed"))
            existing_revision = registration.enrollment_revision

        if existing_revision < registration.acknowledgement_revision:
            result = self.store.acknowledge_relay_sender_keys(
                device_id=registration.device_id,
                revision=registration.acknowledgement_revision,
                sender_key_revision=registration.sender_key_revision,
                acknowledged_sender_key_ids=acknowledged_ids,
                normalized_body=registration.wire_value(),
                now=now,
            )
            changed = changed or bool(result.get("changed"))
        else:
            current = self.store.get_device(registration.device_id) or {}
            if (
                int(current.get("sender_key_revision") or 0)
                != registration.sender_key_revision
                or current.get("acknowledged_sender_key_ids") != sorted(acknowledged_ids)
            ):
                raise ValueError("Loopdy Link relay readiness conflicts with the local acknowledgement")

        return {
            "ready": True,
            "changed": changed,
            "device_id": registration.device_id,
            "revision": registration.acknowledgement_revision,
        }

    def set_provider_mode(self, mode: str) -> dict[str, Any]:
        self._assert_open()
        normalized = str(mode or "").strip().lower()
        retire: Any | None = None
        with self._provider_lock:
            if normalized == "direct":
                try:
                    config = load_apns_config(self.store.load_apns_config() or {})
                except ValueError as error:
                    raise ValueError("Configure APNs before selecting the direct provider") from error
                previous = self._providers.get("direct")
                replacement = ApnsPushProvider(config)
                self._reset_provider_bookkeeping_locked(replacement)
                self._providers["direct"] = replacement
                retire = previous
            elif normalized == "relay":
                try:
                    self._provider("relay")
                except (ValueError, DeliveryError) as error:
                    raise ValueError("Configure relay before selecting the relay provider") from error
            elif normalized == "managed":
                previous = self._providers.pop("direct", None)
                retire = previous
            self.store.set_provider_mode(normalized)
        if retire is not None:
            self._retire_provider(retire)
        return self.health()

    def configure_relay(self, config: RelayConfig) -> dict[str, Any]:
        self._assert_open()
        if not isinstance(config, RelayConfig):
            raise ValueError("Relay configuration is invalid")
        replacement = RelayPushProvider(RelayClient(config))
        try:
            replacement.client.validate_local_credentials()
        except Exception:
            replacement.close()
            raise
        previous: Any | None = None
        try:
            with self._provider_lock:
                self._assert_open()
                self.store.save_relay_config(config.stored_values())
                previous = self._providers.get("relay")
                self._reset_provider_bookkeeping_locked(replacement)
                self._providers["relay"] = replacement
                self.store.set_provider_mode("relay")
        except Exception:
            replacement.close()
            raise
        if previous is not None and previous is not replacement:
            self._retire_provider(previous)
        return self.health()

    def remove_relay_configuration(self) -> dict[str, Any]:
        self._assert_open()
        previous: Any | None = None
        with self._provider_lock:
            previous = self._providers.pop("relay", None)
            self.store.clear_relay_config()
            if self.store.provider_mode() == "relay":
                self.store.set_provider_mode("managed")
        if previous is not None:
            self._retire_provider(previous)
        return self.health()

    def _resume_queued_relay_events(self) -> None:
        """Resume bounded, durable relay alert work after a process restart."""
        if self._closed or self._closing:
            return
        self._ensure_worker()
        for row in self.store.queued_relay_events(limit=100):
            try:
                event = LoopdyEvent(
                    event_id=str(row["event_id"]),
                    type=str(row["type"]),
                    profile=str(row.get("profile") or "default"),
                    session_id=str(row.get("session_id") or ""),
                    job_id=str(row.get("job_id") or ""),
                    task_id=str(row.get("task_id") or ""),
                    approval_id=str(row.get("approval_id") or ""),
                    delegation_id=str(row.get("delegation_id") or ""),
                    detail=row.get("detail") if isinstance(row.get("detail"), Mapping) else {},
                )
                self._queue.put_nowait((event, str(row.get("target") or "all")))
            except (queue.Full, ValueError, TypeError) as error:
                logger.warning(
                    "Loopdy queued relay event could not be resumed: %s",
                    _safe_error(error),
                )

    def register_device(
        self,
        *,
        device_id: str,
        endpoint_id: str,
        provider: str | None = None,
        token_environment: str = "production",
        label: str = "",
        groups: list[str] | None = None,
        preferences: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_open()
        active_mode = self.store.provider_mode()
        selected_provider = str(provider or active_mode).strip().lower()
        if selected_provider not in {"managed", "direct"}:
            raise ValueError("Use revisioned relay registration for relay devices")
        normalized_groups = list(groups or [])
        _validate_device_routing(device_id, normalized_groups)
        _validate_endpoint(selected_provider, endpoint_id)
        if selected_provider == "direct":
            try:
                load_apns_config(self.store.load_apns_config() or {})
            except ValueError as error:
                raise ValueError("Configure APNs before registering direct devices") from error
        normalized_environment = str(token_environment or "production").strip().lower()
        if normalized_environment not in {"production", "sandbox"}:
            raise ValueError("Token environment must be production or sandbox")
        self.store.upsert_device(
            device_id=device_id,
            endpoint_id=endpoint_id,
            provider=selected_provider,
            token_environment=normalized_environment,
            label=label,
            groups=normalized_groups,
            preferences=preferences,
        )
        return {
            "registered": True,
            "device_id": device_id,
            "provider": selected_provider,
        }

    def register_live_activity(
        self,
        *,
        session_id: str,
        live_session_id: str,
        profile: str,
        activity_id: str,
        push_token: str,
        token_environment: str,
    ) -> dict[str, Any]:
        self._assert_open()
        try:
            load_apns_config(self.store.load_apns_config() or {}, environ={})
            provider = self._provider("direct")
        except (ValueError, DeliveryError) as error:
            raise ValueError(
                "Configure direct APNs before registering Live Activities"
            ) from error
        if not isinstance(provider, ApnsPushProvider):
            raise ValueError("Direct APNs is required for Live Activities")
        self.store.upsert_live_activity(
            session_id=session_id,
            live_session_id=live_session_id,
            profile=profile,
            activity_id=activity_id,
            push_token=push_token,
            token_environment=token_environment,
        )
        return {"registered": True, "activity_id": activity_id}

    def relay_operation(self, operation: str, body: Mapping[str, Any]) -> dict[str, Any]:
        self._assert_open()
        normalized_operation = _relay_operation_name(operation)
        if normalized_operation not in {
            "register_device",
            "acknowledge_sender_keys",
            "revoke_device",
            "register_live_activity",
            "revoke_live_activity",
            "revoke_tenant",
            "delete_tenant",
        }:
            raise ValueError("Unknown relay operation")
        normalized = self._validate_relay_operation_body(normalized_operation, body)
        key_name = "device_id" if "device_id" in normalized else (
            "activity_id" if "activity_id" in normalized else "tenant_id"
        )
        operation_key = str(normalized.get(key_name) or "")
        if not operation_key:
            raise ValueError("Relay operation owner is required")
        pending = self.store.pending_relay_operation(normalized_operation, operation_key)
        if pending is None:
            generation = self.store.relay_config_generation()
            self.store.save_pending_relay_operation(
                operation=normalized_operation,
                device_id=operation_key,
                revision=normalized["revision"],
                idempotency_key=normalized["idempotency_key"],
                body=normalized,
                relay_generation=generation,
            )
            pending = self.store.pending_relay_operation(normalized_operation, operation_key)
        else:
            generation = int(pending.get("relay_generation") or 0)
            stored_digest = str(pending.get("request_digest") or "")
            try:
                stored = json.loads(str(pending["body_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                self.store.quarantine_relay_operation(normalized_operation, operation_key, error=str(error))
                raise ValueError("Stored relay operation request is invalid") from error
            if not isinstance(stored, dict):
                self.store.quarantine_relay_operation(normalized_operation, operation_key, error="invalid request")
                raise ValueError("Stored relay operation request is invalid")
            if stored_digest and stored_digest != _request_digest(normalized):
                if not _can_resume_relay_registration(stored, normalized_operation, normalized):
                    raise ValueError("Relay operation request conflict")
            if int(pending.get("terminal") or 0):
                if not stored_digest or not self.store.reset_relay_operation(
                    normalized_operation, operation_key, request_digest=stored_digest
                ):
                    raise DeliveryError("relay_operation_terminal", retryable=False)
                pending = self.store.pending_relay_operation(normalized_operation, operation_key)
                if pending is None:
                    raise DeliveryError("relay_operation_terminal", retryable=False)
                generation = int(pending.get("relay_generation") or 0)
            normalized = stored
        if pending is None:
            raise DeliveryError("relay_operation_pending", retryable=True)
        response = self._process_relay_operation_row(pending, normalized_operation, ignore_due=True)
        if response is None:
            raise DeliveryError("relay_operation_pending", retryable=True)
        return response

    def _validate_relay_operation_body(
        self, operation: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        config = self.store.load_relay_config()
        normalized = normalize_relay_operation(
            operation,
            body,
            tenant_id=None if config is None else str(config.get("tenant_id") or ""),
        )
        # Store JSON uses the same finite, deterministic encoding as the
        # relay client; this also rejects non-serializable values before the
        # journal can be created.
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return normalized

    def _process_relay_operation_row(
        self, pending: Mapping[str, Any], operation: str, *, ignore_due: bool = False
    ) -> dict[str, Any] | None:
        operation_key = str(pending["device_id"])
        # Claim response-ready rows as well as remote-ready rows.  Applying a
        # persisted response is local work, but it is still single-owner work
        # and must retain the claim through apply+clear.
        claimed_row = self.store.claim_pending_relay_operation(
            operation, operation_key, ignore_due=ignore_due
        )
        if claimed_row is None:
            return None
        pending = claimed_row
        claim_token = str(claimed_row["claim_token"])
        digest = str(pending.get("request_digest") or _request_digest(json.loads(str(pending["body_json"]))))
        response_value = str(pending.get("response_json") or "")
        if response_value:
            try:
                response = json.loads(response_value)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                self.store.quarantine_relay_operation(
                    operation,
                    operation_key,
                    error=str(error),
                    claim_token=claim_token,
                    request_digest=digest,
                    relay_generation=int(pending.get("relay_generation") or 0),
                )
                return None
            if not isinstance(response, dict):
                self.store.quarantine_relay_operation(
                    operation,
                    operation_key,
                    error="invalid response",
                    claim_token=claim_token,
                    request_digest=digest,
                    relay_generation=int(pending.get("relay_generation") or 0),
                )
                return None
        else:
            generation = int(claimed_row.get("relay_generation") or 0)
            retry_delay = min(300, 2 ** min(8, int(pending.get("attempts") or 1)))
            if generation != self.store.relay_config_generation():
                self.store.defer_relay_operation(
                    operation=operation,
                    device_id=operation_key,
                    claim_token=claim_token,
                    request_digest=digest,
                    delay_seconds=1,
                    failure="stale relay configuration",
                    terminal=True,
                )
                return None
            try:
                provider = self._provider("relay")
                client = getattr(provider, "client", None)
                if client is None:
                    raise ValueError("Configured relay provider is invalid")
                with self._provider_lease_for(provider):
                    response = getattr(client, operation)(json.loads(str(pending["body_json"])))
                if not isinstance(response, Mapping):
                    raise ValueError("Relay response is invalid")
                if not self.store.record_relay_operation_response(
                    operation=operation,
                    device_id=operation_key,
                    response=dict(response),
                    claim_token=claim_token,
                    request_digest=digest,
                    relay_generation=generation,
                    keep_claim=True,
                ):
                    return None
            except (RelayOutcomeUnknown, DeliveryError) as error:
                self.store.defer_relay_operation(
                    operation=operation,
                    device_id=operation_key,
                    claim_token=claim_token,
                    request_digest=digest,
                    delay_seconds=retry_delay,
                    failure=_safe_error(error),
                    terminal=isinstance(error, DeliveryError) and not error.retryable,
                )
                self._wake_recovery_owner(retry_delay)
                raise
            except Exception as error:
                self.store.defer_relay_operation(
                    operation=operation,
                    device_id=operation_key,
                    claim_token=claim_token,
                    request_digest=digest,
                    delay_seconds=1,
                    failure=_safe_error(error),
                    terminal=True,
                )
                self._wake_recovery_owner(1)
                raise
            response = dict(response)
        body = json.loads(str(pending["body_json"]))
        if not isinstance(body, dict):
            return None
        generation = int(pending.get("relay_generation") or 0)
        if not self.store.relay_operation_claim_active(
            operation,
            operation_key,
            claim_token=claim_token,
            request_digest=digest,
            relay_generation=generation,
        ):
            return None
        self._apply_relay_operation(operation, operation_key, body, response, expected_generation=generation)
        self.store.clear_pending_relay_operation(
            operation,
            operation_key,
            claim_token=claim_token,
            request_digest=digest,
            relay_generation=generation,
        )
        if operation in {"revoke_tenant", "delete_tenant"}:
            self._evict_relay_provider()
        return response

    def _apply_relay_operation(
        self,
        operation: str,
        operation_key: str,
        body: Mapping[str, Any],
        response: Mapping[str, Any],
        *,
        expected_generation: int,
        terminal_claim_token: str = "",
        terminal_request_digest: str = "",
    ) -> None:
        if operation == "register_device":
            self.store.register_relay_device(
                device_id=str(body["device_id"]),
                recipient_public_key=str(body["recipient_public_key"]),
                recipient_key_id=str(body["recipient_key_id"]),
                revision=body["revision"],
                lease_expires=body["lease_expires"],
                normalized_body=body,
                token_environment=str(body["environment"]),
                label=str(body.get("label") or ""),
                groups=list(body.get("groups") or []),
                expected_relay_generation=expected_generation,
                terminal_claim_token=terminal_claim_token,
                terminal_request_digest=terminal_request_digest,
            )
        elif operation == "acknowledge_sender_keys":
            self.store.acknowledge_relay_sender_keys(
                device_id=str(body["device_id"]),
                revision=body["revision"],
                sender_key_revision=body["sender_key_revision"],
                acknowledged_sender_key_ids=list(body["acknowledged_sender_key_ids"]),
                normalized_body=body,
                expected_relay_generation=expected_generation,
            )
        elif operation in {"revoke_device", "device_revoke"}:
            self.store.revoke_relay_device(
                device_id=str(body["device_id"]),
                revision=body["revision"],
                normalized_body=body,
                expected_relay_generation=expected_generation,
            )
        elif operation == "register_live_activity":
            device = self.store.get_device(str(body["device_id"]))
            if (
                device is None
                or device.get("provider") != "relay"
                or device.get("revoked")
                or int(device.get("relay_generation") or 0) != expected_generation
            ):
                raise ValueError("Relay Live Activity device is not active for this generation")
            self.store.register_relay_live_activity(
                activity_id=str(body["activity_id"]),
                device_id=str(body["device_id"]),
                session_ref=str(body["session_ref"]),
                revision=body["revision"],
                timestamp=body["timestamp"],
                lease_expires=body["lease_expires"],
                normalized_body=body,
                expected_relay_generation=expected_generation,
            )
        elif operation == "revoke_live_activity":
            self.store.revoke_relay_live_activity(
                activity_id=str(body["activity_id"]),
                revision=body["revision"],
                timestamp=body["timestamp"],
                normalized_body=body,
                expected_relay_generation=expected_generation,
            )
        elif operation == "revoke_tenant":
            self.store.revoke_relay_tenant(expected_relay_generation=expected_generation)
            self.store.set_provider_mode("managed")
        elif operation == "delete_tenant":
            self.store.revoke_relay_tenant(
                clear_config=True,
                expected_relay_generation=expected_generation,
            )
            self.store.set_provider_mode("managed")
        else:
            raise ValueError("Unknown relay operation")

    def reconcile_relay_operations(self) -> int:
        self._assert_open()
        recovered = 0
        # Claim one row at a time.  A network call can outlive the claim
        # lease; leasing a whole page up front would make unrelated rows
        # appear in-flight and inflate their retry counters while the first
        # row is blocked.  The loop remains bounded for one recovery pass.
        for _ in range(100):
            claimed = self.store.claim_pending_relay_operations(limit=1)
            if not claimed:
                break
            pending = claimed[0]
            operation = _relay_operation_name(pending["operation"])
            operation_key = str(pending["device_id"])
            try:
                body = json.loads(str(pending["body_json"]))
                if not isinstance(body, dict):
                    raise ValueError("invalid request")
                try:
                    body = self._validate_relay_operation_body(operation, body)
                except ValueError as error:
                    self.store.quarantine_relay_operation(
                        operation, operation_key, error=str(error),
                        claim_token=str(pending.get("claim_token") or ""),
                        request_digest=str(pending.get("request_digest") or ""),
                        relay_generation=int(pending.get("relay_generation") or 0),
                    )
                    continue
                digest = str(pending.get("request_digest") or _request_digest(body))
                response_value = str(pending.get("response_json") or "")
                if response_value:
                    response = json.loads(response_value)
                else:
                    if int(pending.get("relay_generation") or 0) != self.store.relay_config_generation():
                        self.store.defer_relay_operation(
                            operation=operation, device_id=operation_key,
                            claim_token=str(pending["claim_token"]), request_digest=digest,
                            delay_seconds=1, failure="stale relay configuration", terminal=True,
                        )
                        continue
                    provider = self._provider("relay")
                    if not hasattr(provider, "client"):
                        raise ValueError("Configured relay provider is invalid")
                    with self._provider_lease_for(provider):
                        response = getattr(provider.client, operation)(body)
                    if not self.store.record_relay_operation_response(
                        operation=operation, device_id=operation_key, response=response,
                        claim_token=str(pending["claim_token"]), request_digest=digest,
                        relay_generation=int(pending.get("relay_generation") or 0),
                        keep_claim=True,
                    ):
                        continue
                if not isinstance(response, dict):
                    raise ValueError("Stored relay operation response is invalid")
                if not self.store.relay_operation_claim_active(
                    operation,
                    operation_key,
                    claim_token=str(pending.get("claim_token") or ""),
                    request_digest=digest,
                    relay_generation=int(pending.get("relay_generation") or 0),
                ):
                    continue
                self._apply_relay_operation(
                    operation,
                    operation_key,
                    body,
                    response,
                    expected_generation=int(pending.get("relay_generation") or 0),
                )
                self.store.clear_pending_relay_operation(
                    operation, operation_key,
                    claim_token=str(pending.get("claim_token") or ""),
                    request_digest=digest,
                    relay_generation=int(pending.get("relay_generation") or 0),
                )
                if operation in {"revoke_tenant", "delete_tenant"}:
                    self._evict_relay_provider()
                recovered += 1
            except (RelayOutcomeUnknown, DeliveryError) as error:
                retry_delay = min(300, 2 ** min(8, int(pending.get("attempts") or 1)))
                self.store.defer_relay_operation(
                    operation=operation, device_id=operation_key,
                    claim_token=str(pending.get("claim_token") or ""),
                    request_digest=str(pending.get("request_digest") or _request_digest(body)),
                    delay_seconds=retry_delay,
                    failure=_safe_error(error),
                    terminal=isinstance(error, DeliveryError) and not error.retryable,
                )
                if not (isinstance(error, DeliveryError) and not error.retryable):
                    self._wake_recovery_owner(retry_delay)
            except Exception as error:
                self.store.quarantine_relay_operation(
                    operation, operation_key, error=_safe_error(error),
                    claim_token=str(pending.get("claim_token") or ""),
                    request_digest=str(pending.get("request_digest") or ""),
                    relay_generation=int(pending.get("relay_generation") or 0),
                )
                logger.warning("Loopdy relay operation recovery failed: %s", _safe_error(error))
        return recovered

    def recover_terminal_relay_registrations(self) -> dict[str, int]:
        """Apply exact legacy provider-conflict responses without relay I/O."""
        self._assert_open()
        totals = {"claimed": 0, "applied": 0, "skipped": 0, "remote_calls": 0}
        for pending in self.store.claim_terminal_provider_conflict_registrations(limit=10):
            totals["claimed"] += 1
            device_id = str(pending["device_id"])
            claim_token = str(pending["claim_token"])
            request_digest = str(pending["request_digest"])
            relay_generation = int(pending["relay_generation"])
            try:
                body = json.loads(str(pending["body_json"]))
                response = json.loads(str(pending["response_json"]))
                if not isinstance(body, dict) or not isinstance(response, dict):
                    raise ValueError("Stored relay registration is invalid")
                normalized = self._validate_relay_operation_body("register_device", body)
                if request_digest != _request_digest(normalized):
                    raise ValueError("Stored relay registration digest is invalid")
                self._validate_stored_relay_registration_response(response, normalized)
                if relay_generation != self.store.relay_config_generation():
                    raise ValueError("Stored relay registration generation is stale")
                self._apply_relay_operation(
                    "register_device", device_id, normalized, response,
                    expected_generation=relay_generation,
                    terminal_claim_token=claim_token,
                    terminal_request_digest=request_digest,
                )
                totals["applied"] += 1
            except Exception:
                self.store.release_terminal_provider_conflict_registration(
                    device_id=device_id,
                    claim_token=claim_token,
                    request_digest=request_digest,
                    relay_generation=relay_generation,
                )
                totals["skipped"] += 1
        return totals

    def _validate_stored_relay_registration_response(
        self, response: Mapping[str, Any], body: Mapping[str, Any]
    ) -> None:
        values = self.store.load_relay_config()
        if not isinstance(values, Mapping):
            raise ValueError("Relay configuration is unavailable")
        config = RelayConfig(**dict(values))
        validate_registration_response(
            response,
            body,
            tenant_id=config.tenant_id,
            sender_keyring=local_sender_key_set(config.signing_key_secret_reference),
        )

    def _evict_relay_provider(self) -> None:
        with self._provider_lock:
            provider = self._providers.pop("relay", None)
        if provider is not None:
            self._retire_provider(provider)

    def enqueue_live_activity_update(self, **update: Any) -> bool:
        with self._live_activity_lifecycle_lock:
            if self._closed or self._closing:
                return False
            self._ensure_live_activity_worker()
            try:
                self._live_activity_queue.put_nowait(dict(update))
                return True
            except queue.Full:
                logger.warning("Loopdy Live Activity update queue is full")
                return False

    def update_live_activities(
        self,
        *,
        session_id: str,
        profile: str,
        status: str = "",
        detail: str = "",
        phase: str = "",
        tool_name: str = "",
        active_session_count: int = 1,
    ) -> dict[str, Any]:
        self._assert_open()
        normalized_phase = _live_activity_phase(phase or status)
        activities = [
            {**activity, "delivery_provider": "direct"}
            for activity in self.store.active_live_activities(session_id, profile)
        ]
        activities.extend(
            {
                **activity,
                "delivery_provider": "relay",
            }
            for activity in self.store.active_relay_live_activities(
                _session_reference(session_id)
            )
        )
        if not activities:
            return {"matched": 0, "delivered": 0, "failed": 0}
        delivered = 0
        failed = 0
        for activity in activities:
            activity_id = str(activity["activity_id"])
            delivery_provider = str(activity["delivery_provider"])
            try:
                with self.store.live_activity_send_lock(activity_id):
                    current_activity = (
                        self.store.active_relay_live_activity(
                            activity_id,
                            expected_session_ref=str(activity["session_ref"]),
                            expected_device_id=str(activity["device_id"]),
                            expected_revision=int(activity["revision"]),
                            expected_lease_expires=int(activity["lease_expires"]),
                        )
                        if delivery_provider == "relay"
                        else self.store.active_live_activity(
                            activity_id,
                            expected_session_id=str(activity["session_id"]),
                            expected_live_session_id=str(activity["live_session_id"]),
                            expected_profile=str(activity["profile"]),
                            expected_push_token=str(activity["push_token"]),
                        )
                    )
                    if current_activity is None:
                        continue
                    current_activity = {
                        **current_activity,
                        "delivery_provider": delivery_provider,
                    }
                    pending = (
                        self.store.pending_relay_live_activity_update(activity_id)
                        if delivery_provider == "relay"
                        else self.store.pending_live_activity_update(activity_id)
                    )
                    if pending is not None:
                        pending_status = str(pending["status"])
                        pending_terminal = bool(int(pending.get("terminal") or 0)) or pending_status in {
                            "completed", "failed"
                        }
                        current_terminal = normalized_phase in {"completed", "failed"}
                        routine = {"thinking", "running"}
                        replace_exhausted_routine = (
                            pending_terminal
                            and pending_status in routine
                            and normalized_phase in {"waiting", "completed", "failed"}
                        )
                        replace_routine_with_waiting = (
                            not pending_terminal
                            and pending_status in routine
                            and normalized_phase == "waiting"
                        )
                        if (current_terminal and not pending_terminal) or replace_exhausted_routine or replace_routine_with_waiting:
                            if delivery_provider == "relay":
                                self._clear_relay_pending(current_activity, pending)
                            else:
                                self.store.clear_pending_live_activity_update(
                                    activity_id,
                                    expected_session_id=str(current_activity["session_id"]),
                                    expected_live_session_id=str(current_activity["live_session_id"]),
                                    expected_profile=str(current_activity["profile"]),
                                    expected_push_token=str(current_activity["push_token"]),
                                    expected_owner_generation=int(current_activity.get("owner_generation") or 0),
                                    expected_request_id=str(pending.get("request_id") or ""),
                                )
                            pending = None
                        else:
                            continue
                    relay_request = None
                    if delivery_provider == "relay":
                        relay_request = self._prepare_relay_live_activity_request(
                            current_activity,
                            status=normalized_phase,
                            active_session_count=active_session_count,
                            pending=pending,
                        )
                        self.store.defer_relay_live_activity_update(
                            activity_id=activity_id,
                            status=normalized_phase,
                            detail="",
                            tool_name="",
                            active_session_count=active_session_count,
                            delay_seconds=0,
                            failure="",
                            timestamp=int(relay_request["timestamp"]),
                            delivery_id=str(relay_request["delivery_id"]),
                            idempotency_key=str(relay_request["idempotency_key"]),
                            request_body=relay_request["request_body"],
                            **self._relay_activity_owner(current_activity),
                        )
                    try:
                        self._send_live_activity_update(
                            current_activity,
                            status=normalized_phase,
                            detail="",
                            tool_name="",
                            active_session_count=active_session_count,
                            relay_request=relay_request,
                        )
                        delivered += 1
                        if delivery_provider == "relay":
                            if normalized_phase in {"completed", "failed"}:
                                assert relay_request is not None
                                self.store.end_relay_live_activity(
                                    activity_id,
                                    expected_session_ref=str(current_activity["session_ref"]),
                                    expected_device_id=str(current_activity["device_id"]),
                                    expected_revision=int(current_activity["revision"]),
                                    expected_delivery_id=str(relay_request["delivery_id"]),
                                    expected_idempotency_key=str(relay_request["idempotency_key"]),
                                )
                            else:
                                self._clear_relay_pending(current_activity, pending or relay_request)
                        elif pending is not None and normalized_phase not in {"completed", "failed"}:
                            self.store.clear_pending_live_activity_update(
                                activity_id,
                                expected_session_id=str(current_activity["session_id"]),
                                expected_live_session_id=str(current_activity["live_session_id"]),
                                expected_profile=str(current_activity["profile"]),
                                expected_push_token=str(current_activity["push_token"]),
                                expected_owner_generation=int(current_activity.get("owner_generation") or 0),
                                expected_request_id=str((pending or {}).get("request_id") or ""),
                            )
                        if normalized_phase in {"completed", "failed"}:
                            if delivery_provider != "relay":
                                self.store.end_live_activity(
                                    activity_id,
                                    expected_session_id=str(current_activity["session_id"]),
                                    expected_live_session_id=str(current_activity["live_session_id"]),
                                    expected_profile=str(current_activity["profile"]),
                                    expected_push_token=str(current_activity["push_token"]),
                                    expected_owner_generation=int(current_activity.get("owner_generation") or 0),
                                    expected_request_id=str((pending or {}).get("request_id") or ""),
                                )
                    except Exception as error:
                        failed += 1
                        logger.warning(
                            "Loopdy Live Activity update failed for %s: %s",
                            activity_id,
                            _safe_error(error),
                        )
                        if isinstance(error, DeliveryError) and error.invalid_token:
                            if delivery_provider == "relay":
                                self.store.end_relay_live_activity(
                                    activity_id,
                                    expected_session_ref=str(current_activity["session_ref"]),
                                    expected_device_id=str(current_activity["device_id"]),
                                    expected_revision=int(current_activity["revision"]),
                                    expected_delivery_id=str((relay_request or {}).get("delivery_id") or ""),
                                    expected_idempotency_key=str((relay_request or {}).get("idempotency_key") or ""),
                                )
                            else:
                                self.store.end_live_activity(
                                    activity_id,
                                    expected_session_id=str(current_activity["session_id"]),
                                    expected_live_session_id=str(current_activity["live_session_id"]),
                                    expected_profile=str(current_activity["profile"]),
                                    expected_push_token=str(current_activity["push_token"]),
                                    expected_owner_generation=int(current_activity.get("owner_generation") or 0),
                                    expected_request_id=str((pending or {}).get("request_id") or ""),
                                )
                        elif (
                            isinstance(error, RelayOutcomeUnknown)
                            or (isinstance(error, DeliveryError) and error.retryable)
                        ):
                            defer = (
                                self.store.defer_relay_live_activity_update
                                if delivery_provider == "relay"
                                else self.store.defer_live_activity_update
                            )
                            defer(
                                activity_id=activity_id,
                                status=normalized_phase,
                                detail="",
                                tool_name="",
                                active_session_count=active_session_count,
                                delay_seconds=1,
                                failure=_safe_error(error),
                                **(
                                    {
                                        "timestamp": int(relay_request["timestamp"]),
                                        "delivery_id": str(relay_request["delivery_id"]),
                                        "idempotency_key": str(relay_request["idempotency_key"]),
                                        "request_body": relay_request["request_body"],
                                        "expected_delivery_id": str(relay_request["delivery_id"]),
                                        "expected_idempotency_key": str(relay_request["idempotency_key"]),
                                    }
                                    if delivery_provider == "relay" and relay_request is not None
                                    else {}
                                ),
                                **(
                                    self._relay_activity_owner(current_activity)
                                    if delivery_provider == "relay"
                                    else {
                                        "expected_session_id": str(current_activity["session_id"]),
                                        "expected_live_session_id": str(current_activity["live_session_id"]),
                                        "expected_profile": str(current_activity["profile"]),
                                        "expected_push_token": str(current_activity["push_token"]),
                                        "expected_owner_generation": int(current_activity.get("owner_generation") or 0),
                                        "expected_request_id": str((pending or {}).get("request_id") or ""),
                                    }
                                ),
                            )
                            if not self._closed:
                                self._ensure_live_activity_worker()
                        elif delivery_provider == "relay":
                            self._clear_relay_pending(current_activity, pending or relay_request)
                        elif pending is not None:
                            self.store.clear_pending_live_activity_update(
                                activity_id,
                                expected_session_id=str(current_activity["session_id"]),
                                expected_live_session_id=str(current_activity["live_session_id"]),
                                expected_profile=str(current_activity["profile"]),
                                expected_push_token=str(current_activity["push_token"]),
                                expected_owner_generation=int(current_activity.get("owner_generation") or 0),
                                expected_request_id=str(pending.get("request_id") or ""),
                            )
            except Exception as error:
                failed += 1
                logger.warning(
                    "Loopdy Live Activity serialization failed for %s: %s",
                    activity_id,
                    _safe_error(error),
                )
        return {"matched": len(activities), "delivered": delivered, "failed": failed}

    def update_device_preferences(
        self,
        device_id: str,
        preferences: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not self.store.update_preferences(device_id, preferences):
            raise ValueError("Unknown or revoked Loopdy device")
        return {"updated": True, "device_id": device_id}

    def revoke_device(self, device_id: str) -> dict[str, Any]:
        self._assert_open()
        device = self.store.get_device(device_id)
        if device is not None and device.get("provider") == "relay":
            if (
                not self.store.relay_config_enabled()
                or int(device.get("relay_generation") or 0) != self.store.relay_config_generation()
            ):
                raise ValueError("Relay device configuration is stale; re-register before revoking")
            revision = int(device.get("revision") or 0) + 1
            pending = self.store.pending_relay_operation("revoke_device", str(device["device_id"]))
            revoke_body: Mapping[str, Any] = {
                "version": 1,
                "device_id": str(device["device_id"]),
                "revision": revision,
                "idempotency_key": str(uuid.uuid4()),
            }
            if pending is not None:
                try:
                    stored_body = json.loads(str(pending["body_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise ValueError("Stored relay operation request is invalid") from error
                if not isinstance(stored_body, dict):
                    raise ValueError("Stored relay operation request is invalid")
                revoke_body = stored_body
            response = self.relay_operation(
                "device_revoke",
                revoke_body,
            )
            return {"revoked": True, "device_id": device_id, "relay": response}
        if not self.store.revoke_device(device_id):
            raise ValueError("Unknown or already revoked Loopdy device")
        return {"revoked": True, "device_id": device_id}

    def test_notification(self, target: str = "all", *, profile: str = "default") -> dict[str, Any]:
        from .events import build_event

        return self.deliver(
            build_event(
                "attention.required",
                profile=profile,
                detail={"message": "Loopdy test notification"},
            ),
            target=target,
        )

    def enqueue(self, event: LoopdyEvent, *, target: str) -> bool:
        if self._closed or self._closing:
            return False
        self.store.record_event(event, target=target)
        self._ensure_worker()
        try:
            self._queue.put_nowait((event, target))
            return True
        except queue.Full:
            self.store.mark_event_failed(event.event_id, "Loopdy delivery queue is full")
            logger.warning("Loopdy delivery queue is full; dropped %s", event.event_id)
            return False

    def deliver(self, event: LoopdyEvent, *, target: str) -> dict[str, Any]:
        self._assert_open()
        verdict = validate_target(target)
        if verdict is not True:
            return {"error": str(verdict), "event_id": event.event_id}
        self.store.record_event(event, target=target)
        devices = self.store.resolve_devices(target)
        if not devices:
            message = f"No compatible Loopdy devices match {target}"
            self.store.mark_event_failed(event.event_id, message)
            return {"error": message, "event_id": event.event_id}

        existing = {
            item["device_id"]: item
            for item in self.store.list_event_deliveries(event.event_id)
        }
        delivered = 0
        failed = 0
        suppressed = 0
        queued = 0
        delivery_ids: list[str] = []
        for device in devices:
            mode = str(device["provider"])
            previous = existing.get(device["device_id"])
            if (
                mode == "relay"
                and previous is not None
                and previous["status"] == "queued"
                and (
                    int(previous.get("target_generation") or 0)
                    != int(device.get("relay_generation") or 0)
                    or int(previous.get("target_revision") or 0)
                    != int(device.get("revision") or 0)
                )
            ):
                previous = None
            if previous is not None:
                if previous["status"] == "sent":
                    delivered += 1
                    if previous.get("delivery_id"):
                        delivery_ids.append(str(previous["delivery_id"]))
                    continue
                elif previous["status"] == "suppressed":
                    suppressed += 1
                    continue
                elif not (mode == "relay" and previous["status"] == "queued"):
                    failed += 1
                    continue
            claim_token = ""
            if mode == "relay" and previous is not None and previous["status"] == "queued":
                claimed = self.store.claim_relay_delivery(
                    event_id=event.event_id,
                    device_id=str(device["device_id"]),
                    # A queued row is durable retry work.  Direct callers
                    # must not bypass its next_attempt_at backoff.
                    ignore_due=False,
                )
                if claimed is None:
                    queued += 1
                    continue
                previous = claimed
                claim_token = str(claimed["claim_token"])
            preferences = device.get("preferences") or {}
            suppression = _suppression_reason(event, preferences, self._now())
            if suppression:
                self.store.record_device_delivery(
                    event_id=event.event_id,
                    device_id=device["device_id"],
                    provider=mode,
                    status="suppressed",
                    failure=suppression,
                )
                suppressed += 1
                continue
            target_revision = (
                int((previous or {}).get("target_revision") or device.get("revision") or 0)
                if mode == "relay"
                else 0
            )
            target_key_id = (
                str((previous or {}).get("target_key_id") or device.get("recipient_key_id") or "")
                if mode == "relay"
                else ""
            )
            target_sender_key_id = (
                str((previous or {}).get("target_sender_key_id") or "")
                if mode == "relay"
                else ""
            )
            delivery_id = ""
            idempotency_key = ""
            relay_request_body: dict[str, Any] | None = None
            lease: _ProviderLease | None = None
            try:
                provider = self._provider(mode)
                lease = self._provider_lease_for(provider)
                if mode == "relay":
                    acknowledged = [
                        str(value)
                        for value in device.get("acknowledged_sender_key_ids") or []
                    ]
                    selector = getattr(provider, "select_sender_key_id", None)
                    if not callable(selector):
                        raise ValueError("Relay provider cannot select an acknowledged sender key")
                    if not target_sender_key_id:
                        target_sender_key_id = str(selector(acknowledged))
                    delivery_id, idempotency_key = delivery_coordinates(
                        event.event_id,
                        str(device["device_id"]),
                        target_revision,
                    )
                message = shape_notification(event, preferences)
                if mode == "relay":
                    encoded_body = str((previous or {}).get("relay_request_body_json") or "")
                    if encoded_body:
                        parsed_body = json.loads(encoded_body)
                        if not isinstance(parsed_body, dict):
                            raise ValueError("Stored relay delivery body is invalid")
                        relay_request_body = parsed_body
                    elif isinstance(provider, RelayPushProvider):
                        relay_request_body = provider.prepare_device(
                            {
                                **device,
                                "revision": target_revision,
                                "recipient_key_id": target_key_id,
                                "acknowledged_sender_key_ids": [target_sender_key_id],
                            },
                            message,
                            delivery_id=delivery_id,
                            idempotency_key=idempotency_key,
                        )
            except Exception as error:
                if lease is not None:
                    lease.release()
                failure = _safe_error(error)
                retryable_relay = mode == "relay" and (
                    isinstance(error, RelayOutcomeUnknown)
                    or (isinstance(error, DeliveryError) and error.retryable)
                )
                if claim_token:
                    self.store.finalize_relay_delivery(
                        event_id=event.event_id, device_id=str(device["device_id"]),
                        claim_token=claim_token,
                        status="queued" if retryable_relay else "failed",
                        failure=failure,
                        next_attempt_at=int(time.time()) + (
                            2 ** min(8, max(1, int((previous or {}).get("attempts") or 1)))
                            if retryable_relay else 0
                        ),
                        expected_target_revision=target_revision,
                        expected_target_generation=int(device.get("relay_generation") or 0),
                    )
                elif mode == "relay":
                    self.store.admit_relay_delivery(
                        event_id=event.event_id,
                        device_id=device["device_id"],
                        delivery_id=delivery_id,
                        status="queued" if retryable_relay else "failed",
                        failure=failure,
                        target_revision=target_revision,
                        target_generation=int(device.get("relay_generation") or 0),
                        target_key_id=target_key_id,
                        target_sender_key_id=target_sender_key_id,
                        relay_request_body=relay_request_body,
                    )
                else:
                    self.store.record_device_delivery(
                        event_id=event.event_id,
                        device_id=device["device_id"],
                        provider=mode,
                        status="queued" if retryable_relay else "failed",
                        failure=failure,
                        target_revision=target_revision,
                        target_generation=(
                            int(device.get("relay_generation") or 0) if mode == "relay" else 0
                        ),
                        target_key_id=target_key_id,
                        target_sender_key_id=target_sender_key_id,
                        relay_request_body=relay_request_body,
                    )
                if retryable_relay:
                    queued += 1
                    self._wake_recovery_owner(
                        2 ** min(8, max(1, int((previous or {}).get("attempts") or 1)))
                    )
                else:
                    failed += 1
                continue
            try:
                if not claim_token:
                    if mode == "relay":
                        admitted = self.store.admit_relay_delivery(
                            event_id=event.event_id,
                            device_id=device["device_id"],
                            delivery_id=delivery_id,
                            target_revision=target_revision,
                            target_generation=int(device.get("relay_generation") or 0),
                            target_key_id=target_key_id,
                            target_sender_key_id=target_sender_key_id,
                            relay_request_body=relay_request_body,
                        )
                        previous = admitted
                        admitted_status = str(admitted.get("status") or "queued")
                        if admitted_status == "sent":
                            delivered += 1
                            if admitted.get("delivery_id"):
                                delivery_ids.append(str(admitted["delivery_id"]))
                            if lease is not None:
                                lease.release()
                                lease = None
                            continue
                        if admitted_status != "queued":
                            failed += 1
                            if lease is not None:
                                lease.release()
                                lease = None
                            continue
                        target_revision = int(admitted.get("target_revision") or target_revision)
                        target_key_id = str(admitted.get("target_key_id") or target_key_id)
                        target_sender_key_id = str(
                            admitted.get("target_sender_key_id") or target_sender_key_id
                        )
                        delivery_id = str(admitted.get("delivery_id") or delivery_id)
                        idempotency_key = idempotency_key or str(
                            (relay_request_body or {}).get("idempotency_key") or ""
                        )
                        encoded = str(admitted.get("relay_request_body_json") or "")
                        if encoded:
                            parsed = json.loads(encoded)
                            if not isinstance(parsed, dict):
                                raise ValueError("Stored relay delivery body is invalid")
                            relay_request_body = parsed
                            idempotency_key = str(parsed.get("idempotency_key") or idempotency_key)
                    else:
                        self.store.record_device_delivery(
                            event_id=event.event_id, device_id=device["device_id"], provider=mode,
                            status="queued", target_revision=target_revision,
                            target_generation=0,
                            target_key_id=target_key_id, target_sender_key_id=target_sender_key_id,
                            relay_request_body=relay_request_body,
                        )
                if mode == "relay" and not claim_token:
                    claimed = self.store.claim_relay_delivery(
                        event_id=event.event_id, device_id=str(device["device_id"]), ignore_due=False
                    )
                    if claimed is None:
                        if lease is not None:
                            lease.release()
                            lease = None
                        queued += 1
                        continue
                    previous = claimed
                    claim_token = str(claimed["claim_token"])
                    target_revision = int(claimed.get("target_revision") or target_revision)
                    target_key_id = str(claimed.get("target_key_id") or target_key_id)
                    target_sender_key_id = str(
                        claimed.get("target_sender_key_id") or target_sender_key_id
                    )
                    delivery_id = str(claimed.get("delivery_id") or delivery_id)
                    # The claim returns the frozen body and coordinates that
                    # must remain authoritative across retries.
                    encoded = str(claimed.get("relay_request_body_json") or "")
                    if encoded:
                        parsed = json.loads(encoded)
                        if not isinstance(parsed, dict):
                            raise ValueError("Stored relay delivery body is invalid")
                        relay_request_body = parsed
                        idempotency_key = str(parsed.get("idempotency_key") or idempotency_key)
            except Exception:
                if lease is not None:
                    lease.release()
                    lease = None
                raise
            try:
                if mode == "relay":
                    sender = getattr(provider, "send_device", None)
                    if not callable(sender):
                        raise ValueError("Relay provider is not device-aware")
                    send_kwargs: dict[str, Any] = {
                        "device": {
                            **device,
                            "revision": target_revision,
                            "recipient_key_id": target_key_id,
                            "acknowledged_sender_key_ids": [target_sender_key_id],
                        },
                        "message": message,
                        "delivery_id": delivery_id,
                        "idempotency_key": idempotency_key,
                    }
                    if isinstance(provider, RelayPushProvider):
                        send_kwargs["request_body"] = relay_request_body
                    receipt = sender(**send_kwargs)
                else:
                    receipt = self._send_with_retry(
                        provider,
                        device["endpoint_id"],
                        message,
                        environment=device.get("token_environment") or "",
                    )
            except Exception as error:
                if lease is not None:
                    lease.release()
                failure = _safe_error(error)
                retryable_relay = mode == "relay" and (
                    isinstance(error, RelayOutcomeUnknown)
                    or (isinstance(error, DeliveryError) and error.retryable)
                )
                if claim_token and mode == "relay":
                    self.store.finalize_relay_delivery(
                        event_id=event.event_id, device_id=str(device["device_id"]),
                        claim_token=claim_token,
                        status="queued" if retryable_relay else "failed",
                        failure=failure,
                        next_attempt_at=int(time.time()) + (
                            2 ** min(8, max(1, int((previous or {}).get("attempts") or 1)))
                            if retryable_relay else 0
                        ),
                        expected_target_revision=target_revision,
                        expected_target_generation=int(device.get("relay_generation") or 0),
                    )
                else:
                    self.store.record_device_delivery(
                        event_id=event.event_id, device_id=device["device_id"], provider=mode,
                        status="queued" if retryable_relay else "failed", failure=failure,
                        target_revision=target_revision,
                        target_generation=(int(device.get("relay_generation") or 0) if mode == "relay" else 0),
                        target_key_id=target_key_id, target_sender_key_id=target_sender_key_id,
                        relay_request_body=relay_request_body,
                    )
                if isinstance(error, DeliveryError) and error.invalid_token:
                    self.store.revoke_device(device["device_id"])
                logger.warning(
                    "Loopdy %s delivery failed for event %s device %s: %s",
                    mode,
                    event.event_id,
                    device["device_id"],
                    failure,
                )
                if retryable_relay:
                    queued += 1
                    self._wake_recovery_owner(
                        2 ** min(8, max(1, int((previous or {}).get("attempts") or 1)))
                    )
                else:
                    failed += 1
                continue
            if lease is not None:
                lease.release()
                lease = None
            finalized = (
                self.store.finalize_relay_delivery(
                    event_id=event.event_id, device_id=str(device["device_id"]),
                    claim_token=claim_token, status="sent", delivery_id=receipt.delivery_id,
                    expected_target_revision=target_revision,
                    expected_target_generation=int(device.get("relay_generation") or 0),
                )
                if mode == "relay" else True
            )
            if mode != "relay":
                self.store.record_device_delivery(
                    event_id=event.event_id, device_id=device["device_id"], provider=mode,
                    status="sent", delivery_id=receipt.delivery_id,
                    target_revision=target_revision,
                    target_generation=(int(device.get("relay_generation") or 0) if mode == "relay" else 0),
                    target_key_id=target_key_id, target_sender_key_id=target_sender_key_id,
                )
            if not finalized:
                failed += 1
                continue
            if receipt.pending_receipt_id:
                self.store.record_provider_receipt(
                    receipt_id=receipt.pending_receipt_id,
                    event_id=event.event_id,
                    device_id=device["device_id"],
                    provider=mode,
                )
            delivered += 1
            delivery_ids.append(receipt.delivery_id)

        success = delivered > 0 or (suppressed > 0 and failed == 0)
        if success and queued == 0:
            self.store.mark_event_delivered(
                event.event_id,
                delivery_ids[0] if delivery_ids else event.event_id,
            )
        elif not success and queued == 0:
            self.store.mark_event_failed(event.event_id, "All Loopdy device deliveries failed")
        result: dict[str, Any] = {
            "success": success,
            "event_id": event.event_id,
            "message_id": delivery_ids[0] if delivery_ids else event.event_id,
            "delivered": delivered,
            "failed": failed,
            "suppressed": suppressed,
            "queued": queued,
        }
        if not success:
            result["error"] = "All Loopdy device deliveries failed"
        return result

    def reconcile_receipts(self) -> dict[str, int]:
        self._assert_open()
        totals = {"checked": 0, "delivered": 0, "failed": 0}
        for mode, provider in list(self._providers.items()):
            receipts_fn = getattr(provider, "receipts", None)
            if not callable(receipts_fn):
                continue
            try:
                pending = self.store.pending_provider_receipts(mode, limit=1000)
            except Exception as error:
                logger.warning(
                    "Loopdy %s receipt ledger read failed: %s", mode, _safe_error(error)
                )
                continue
            if not pending:
                continue
            try:
                lease = self._provider_lease_for(provider)
            except DeliveryError:
                continue
            try:
                with lease:
                    results = receipts_fn([item["receipt_id"] for item in pending])
            except Exception as error:
                logger.warning("Loopdy %s receipt reconciliation failed: %s", mode, _safe_error(error))
                continue
            by_id = {item["receipt_id"]: item for item in pending}
            for receipt_id, receipt in results.items():
                item = by_id.get(receipt_id)
                if item is None:
                    continue
                if not self.store.complete_provider_receipt(
                    receipt_id,
                    status=receipt.status,
                    error=receipt.error_code,
                ):
                    continue
                totals["checked"] += 1
                totals[receipt.status] += 1
                if receipt.status == "failed":
                    self.store.record_device_delivery(
                        event_id=item["event_id"],
                        device_id=item["device_id"],
                        provider=mode,
                        status="failed",
                        delivery_id=receipt_id,
                        failure=receipt.error_code,
                    )
                if receipt.invalid_token:
                    self.store.revoke_device(item["device_id"])
        return totals

    def close(self) -> None:
        with self._live_activity_lifecycle_lock:
            if self._closed:
                return
            self._closing = True
        with self._recovery_timer_lock:
            recovery_timer = self._recovery_timer
            self._recovery_timer = None
            self._recovery_timer_due = 0.0
            if recovery_timer is not None:
                recovery_timer.cancel()
        worker = self._worker
        if worker is not None:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            worker.join(timeout=2)
        live_activity_worker = self._live_activity_worker
        if live_activity_worker is not None and live_activity_worker.is_alive():
            while live_activity_worker.is_alive():
                try:
                    self._live_activity_queue.put(None, timeout=0.25)
                    break
                except queue.Full:
                    continue
            live_activity_worker.join()
        with self._provider_lock:
            providers = list(self._providers.values())
            self._providers.clear()
        for provider in providers:
            self._retire_provider(provider)
        with self._live_activity_lifecycle_lock:
            self._closed = True

    def _provider(self, mode: str) -> Any:
        self._assert_open()
        with self._provider_lock:
            self._assert_open()
            provider = self._providers.get(mode)
            if provider is not None:
                return provider
            if mode == "managed":
                provider = ExpoPushProvider()
            elif mode == "direct":
                provider = ApnsPushProvider(load_apns_config(self.store.load_apns_config() or {}))
            elif mode == "relay":
                if not self.store.relay_config_enabled():
                    raise ValueError("Relay configuration is disabled; configuration is missing")
                values = self.store.load_relay_config()
                if values is None:
                    raise ValueError("Relay configuration is missing")
                provider = RelayPushProvider(RelayClient(RelayConfig(**values)))
                try:
                    provider.client.validate_local_credentials()
                except Exception:
                    provider.close()
                    raise
            else:
                raise ValueError("Loopdy provider mode must be managed, direct, or relay")
            self._reset_provider_bookkeeping_locked(provider)
            self._providers[mode] = provider
            return provider

    def _reset_provider_bookkeeping_locked(self, provider: Any) -> None:
        """Clear stale identity state before installing a newly-created provider.

        Provider leases use object identities because providers are not part of
        the public contract and may not be hashable.  An identity can be reused
        by Python after an old provider is closed, so a new provider must never
        inherit that old provider's lifecycle state.
        """
        identifier = id(provider)
        self._provider_identity[identifier] = provider
        self._provider_inflight.pop(identifier, None)
        self._provider_retired.discard(identifier)
        self._provider_close_events.pop(identifier, None)
        self._provider_closed.discard(identifier)

    def _provider_lease(self, mode: str) -> "_ProviderLease":
        self._assert_open()
        with self._provider_lock:
            provider = self._provider(mode)
            identifier = id(provider)
            if identifier in self._provider_closed or identifier in self._provider_retired:
                raise DeliveryError("provider_closing", retryable=True)
            self._provider_inflight[identifier] = self._provider_inflight.get(identifier, 0) + 1
        return _ProviderLease(self, provider)

    def _provider_lease_for(self, provider: Any) -> "_ProviderLease":
        self._assert_open()
        with self._provider_lock:
            if self._provider_identity.get(id(provider)) is not provider:
                raise DeliveryError("provider_closing", retryable=True)
            if (
                not any(candidate is provider for candidate in self._providers.values())
                or id(provider) in self._provider_closed
                or id(provider) in self._provider_retired
            ):
                raise DeliveryError("provider_closing", retryable=True)
            self._provider_inflight[id(provider)] = self._provider_inflight.get(id(provider), 0) + 1
        return _ProviderLease(self, provider)

    def _release_provider(self, provider: Any) -> None:
        should_close = False
        event: threading.Event | None = None
        identifier = id(provider)
        with self._provider_lock:
            count = self._provider_inflight.get(identifier, 0)
            if count <= 1:
                self._provider_inflight.pop(identifier, None)
                event = self._provider_close_events.pop(identifier, None)
                should_close = identifier in self._provider_retired
            else:
                self._provider_inflight[identifier] = count - 1
        if event is not None:
            event.set()
        # A retirement waiter owns close when it has an event.  The final
        # lease only wakes that waiter; both paths must never close the same
        # provider independently.
        if should_close and event is None:
            self._close_provider(provider)

    def _retire_provider(self, provider: Any) -> None:
        identifier = id(provider)
        event: threading.Event | None = None
        with self._provider_lock:
            if self._provider_identity.get(identifier) is not provider:
                return
            if identifier in self._provider_closed or identifier in self._provider_retired:
                return
            self._provider_retired.add(identifier)
            if self._provider_inflight.get(identifier, 0) > 0:
                event = self._provider_close_events.setdefault(identifier, threading.Event())
        if event is not None:
            event.wait()
        self._close_provider(provider)

    def _close_provider(self, provider: Any) -> None:
        identifier = id(provider)
        with self._provider_lock:
            if self._provider_identity.get(identifier) is not provider:
                return
            if identifier in self._provider_closed:
                return
            self._provider_closed.add(identifier)
        close = getattr(provider, "close", None)
        try:
            if callable(close):
                close()
        finally:
            with self._provider_lock:
                self._provider_inflight.pop(identifier, None)
                self._provider_close_events.pop(identifier, None)
                self._provider_retired.discard(identifier)
                self._provider_closed.discard(identifier)
                self._provider_identity.pop(identifier, None)

    def _assert_open(self) -> None:
        with self._live_activity_lifecycle_lock:
            if self._closed:
                raise DeliveryError("service_closed", retryable=False)
            if self._closing:
                # close() drains work already admitted to the Live Activity
                # queue before retiring providers. New callers remain gated.
                if threading.current_thread() is not self._live_activity_worker:
                    raise DeliveryError("service_closing", retryable=False)

    def _send_with_retry(
        self,
        provider: PushProvider,
        token: str,
        message: Any,
        *,
        environment: str,
    ) -> Any:
        for attempt in range(1, self._max_attempts + 1):
            try:
                return provider.send(token, message, environment=environment)
            except DeliveryError as error:
                if not error.retryable or attempt >= self._max_attempts:
                    raise
                delay = 0.25 * (2 ** (attempt - 1)) + min(0.25, max(0.0, self._jitter()) * 0.1)
                self._sleep(delay)
        raise DeliveryError("retry_exhausted", retryable=False)

    def _send_live_activity_update(
        self,
        activity: Mapping[str, Any],
        *,
        status: str,
        detail: str,
        tool_name: str,
        active_session_count: int,
        relay_request: Mapping[str, Any] | None = None,
    ) -> Any:
        phase = _live_activity_phase(status)
        mode = "relay" if str(activity.get("delivery_provider") or "direct") == "relay" else "direct"
        with self._provider_lease(mode) as provider:
            if mode == "relay":
                sender = getattr(provider, "send_live_activity", None)
                if not callable(sender):
                    raise ValueError("Relay provider cannot send Live Activity updates")
                prepared = (
                    relay_request
                    if relay_request is not None and "request_body" in relay_request
                    else self._prepare_relay_live_activity_request(
                        activity,
                        status=phase,
                        active_session_count=active_session_count,
                        pending=relay_request,
                    )
                )
                send_kwargs: dict[str, Any] = {
                    "device_id": str(activity["device_id"]),
                    "state": prepared["state"],
                    "delivery_id": str(prepared["delivery_id"]),
                    "target_revision": int(activity["revision"]),
                    "idempotency_key": str(prepared["idempotency_key"]),
                }
                if isinstance(provider, RelayPushProvider):
                    send_kwargs["request_body"] = prepared["request_body"]
                return sender(**send_kwargs)
            if not isinstance(provider, ApnsPushProvider):
                raise ValueError("Direct APNs is required for Live Activities")
            return self._send_live_activity_with_retry(
                provider,
                str(activity["push_token"]),
                activity_id=str(activity["activity_id"]),
                phase=phase,
                active_session_count=active_session_count,
                session_ref=_session_reference(
                    str(activity.get("live_session_id") or activity.get("session_id") or "")
                ),
                environment=str(activity["token_environment"]),
                _expected_session_id=str(activity["session_id"]),
                _expected_live_session_id=str(activity["live_session_id"]),
                _expected_profile=str(activity["profile"]),
                _expected_owner_generation=int(activity.get("owner_generation") or 0),
            )

    def _prepare_relay_live_activity_request(
        self,
        activity: Mapping[str, Any],
        *,
        status: str,
        active_session_count: int,
        pending: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_body: dict[str, Any] | None = None
        if pending is not None:
            encoded = str(pending.get("request_body_json") or "")
            if encoded:
                try:
                    parsed = json.loads(encoded)
                except (TypeError, json.JSONDecodeError) as error:
                    raise ValueError("Stored relay Live Activity request is invalid") from error
                if not isinstance(parsed, dict):
                    raise ValueError("Stored relay Live Activity request is invalid")
                request_body = parsed
        if request_body is not None:
            try:
                state = LiveActivityState(**request_body["state"])
                timestamp = int(pending.get("timestamp") or state.timestamp)
                delivery_id = str(pending.get("delivery_id") or "")
                idempotency_key = str(pending.get("idempotency_key") or "")
                if (
                    request_body.get("device_id") != str(activity["device_id"])
                    or state.activity_id != str(activity["activity_id"])
                    or state.session_ref != str(activity["session_ref"])
                    or not delivery_id
                    or not idempotency_key
                    or timestamp != state.timestamp
                ):
                    raise ValueError("Stored relay Live Activity request does not match its owner")
                expected_delivery_id, expected_idempotency_key = live_activity_delivery_coordinates(
                    state,
                    str(activity["device_id"]),
                    int(activity["revision"]),
                )
                if (
                    delivery_id != expected_delivery_id
                    or idempotency_key != expected_idempotency_key
                    or state.timestamp <= int(activity.get("source_timestamp") or 0)
                ):
                    raise ValueError("Stored relay Live Activity request does not match its owner")
                return {
                    "state": state,
                    "timestamp": timestamp,
                    "delivery_id": delivery_id,
                    "idempotency_key": idempotency_key,
                    "request_body": request_body,
                }
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("Stored relay Live Activity request is invalid") from error
        timestamp = self.store.allocate_relay_live_activity_timestamp(
            str(activity["activity_id"]),
            int(self._timestamp()),
            expected_session_ref=str(activity["session_ref"]),
            expected_device_id=str(activity["device_id"]),
            expected_revision=int(activity["revision"]),
            expected_lease_expires=int(activity["lease_expires"]),
        )
        state = LiveActivityState(
            version=1,
            kind="live_activity",
            activity_id=str(activity["activity_id"]),
            session_ref=str(activity["session_ref"]),
            phase=status,
            progress=100 if status in {"completed", "failed"} else 0,
            active_session_count=active_session_count,
            timestamp=timestamp,
            expires=timestamp + 120,
        )
        delivery_id, idempotency_key = live_activity_delivery_coordinates(
            state,
            str(activity["device_id"]),
            int(activity["revision"]),
        )
        request_body = {
            "device_id": str(activity["device_id"]),
            "delivery_id": delivery_id,
            "state": state.as_payload(),
            "idempotency_key": idempotency_key,
        }
        return {
            "state": state,
            "timestamp": timestamp,
            "delivery_id": delivery_id,
            "idempotency_key": idempotency_key,
            "request_body": request_body,
        }

    def _relay_activity_owner(self, activity: Mapping[str, Any]) -> dict[str, Any]:
        device = self.store.get_device(str(activity["device_id"]))
        if device is None:
            raise ValueError("Relay Live Activity device is no longer registered")
        return {
            "expected_device_id": str(activity["device_id"]),
            "expected_session_ref": str(activity["session_ref"]),
            "expected_revision": int(activity["revision"]),
            "expected_lease_expires": int(activity["lease_expires"]),
            "expected_relay_generation": int(device.get("relay_generation") or 0),
        }

    def _clear_relay_pending(
        self, activity: Mapping[str, Any], pending: Mapping[str, Any] | None = None
    ) -> bool:
        device = str(activity.get("device_id") or (pending or {}).get("device_id") or "")
        session = str(activity.get("session_ref") or (pending or {}).get("session_ref") or "")
        revision = int(activity.get("revision") or (pending or {}).get("revision") or 0)
        lease = int(activity.get("lease_expires") or (pending or {}).get("lease_expires") or 0)
        generation = int(
            activity.get("relay_generation")
            or (pending or {}).get("relay_generation")
            or (self.store.get_device(device) or {}).get("relay_generation")
            or 0
        )
        return self.store.clear_pending_relay_live_activity_update(
            str(activity.get("activity_id") or (pending or {}).get("activity_id") or ""),
            expected_device_id=device,
            expected_session_ref=session,
            expected_revision=revision,
            expected_lease_expires=lease,
            expected_relay_generation=generation,
            expected_delivery_id=str((pending or {}).get("delivery_id") or ""),
            expected_idempotency_key=str((pending or {}).get("idempotency_key") or ""),
        )

    def _send_live_activity_with_retry(
        self,
        provider: ApnsPushProvider,
        token: str,
        **update: Any,
    ) -> Any:
        expected_session_id = str(update.pop("_expected_session_id", ""))
        expected_live_session_id = str(update.pop("_expected_live_session_id", ""))
        expected_profile = str(update.pop("_expected_profile", ""))
        expected_owner_generation = int(update.pop("_expected_owner_generation", 0) or 0)
        for attempt in range(1, self._max_attempts + 1):
            try:
                timestamp = self.store.allocate_live_activity_timestamp(
                    str(update["activity_id"]),
                    int(self._timestamp()),
                    expected_session_id=expected_session_id,
                    expected_live_session_id=expected_live_session_id,
                    expected_profile=expected_profile,
                    expected_push_token=token,
                    expected_owner_generation=expected_owner_generation,
                )
                phase = str(update["phase"])
                return provider.send_live_activity(
                    token,
                    timestamp=timestamp,
                    expires=timestamp + 120,
                    progress=100 if phase in {"completed", "failed"} else 0,
                    **update,
                )
            except DeliveryError as error:
                if not error.retryable or attempt >= self._max_attempts:
                    raise
                delay = 0.25 * (2 ** (attempt - 1)) + min(
                    0.25, max(0.0, self._jitter()) * 0.1
                )
                self._sleep(delay)
        raise DeliveryError("retry_exhausted", retryable=False)

    def _ensure_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        with self._worker_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._run_worker,
                name="loopdy-delivery",
                daemon=True,
            )
            self._worker.start()
            self._recovery_wakeup.set()

    def _wake_recovery_owner(self, delay_seconds: int = 0) -> None:
        if self._closed or self._closing:
            return
        # A durable row can be created by a synchronous call while the
        # service was otherwise idle.  Ensure the single recovery owner is
        # alive before scheduling its bounded wake-up.
        self._ensure_worker()
        if delay_seconds <= 0:
            with self._recovery_timer_lock:
                recovery_timer = self._recovery_timer
                self._recovery_timer = None
                self._recovery_timer_due = 0.0
                if recovery_timer is not None:
                    recovery_timer.cancel()
            self._recovery_wakeup.set()
            return
        delay = max(0.1, float(delay_seconds))
        due = time.monotonic() + delay
        with self._recovery_timer_lock:
            if self._closed or self._closing:
                return
            if self._recovery_timer is not None and self._recovery_timer_due <= due:
                return
            previous = self._recovery_timer
            if previous is not None:
                previous.cancel()
            timer: threading.Timer
            timer = threading.Timer(delay, lambda: self._fire_recovery_timer(timer))
            timer.daemon = True
            self._recovery_timer = timer
            self._recovery_timer_due = due
            timer.start()

    def _fire_recovery_timer(self, timer: threading.Timer) -> None:
        with self._recovery_timer_lock:
            if self._recovery_timer is not timer:
                return
            self._recovery_timer = None
            self._recovery_timer_due = 0.0
            if self._closed or self._closing:
                return
            self._recovery_wakeup.set()

    def _ensure_live_activity_worker(self) -> None:
        if self._live_activity_worker is not None and self._live_activity_worker.is_alive():
            return
        with self._live_activity_worker_lock:
            if self._live_activity_worker is not None and self._live_activity_worker.is_alive():
                return
            self._live_activity_worker = threading.Thread(
                target=self._run_live_activity_worker,
                name="loopdy-live-activity",
                daemon=True,
            )
            self._live_activity_worker.start()

    def _run_worker(self) -> None:
        last_recovery_scan = 0.0
        while True:
            try:
                item = self._queue.get(timeout=0.25)
            except queue.Empty:
                if self._closed:
                    return
                now = time.monotonic()
                # The wake-up event is an accelerator; the periodic scan is
                # a bounded safety net for due durable rows created by a
                # different process.  Neither path scans on every idle poll.
                if not self._recovery_wakeup.is_set() and now - last_recovery_scan < 10.0:
                    continue
                self._recovery_wakeup.clear()
                try:
                    # The database is the durable source of truth. The
                    # in-memory queue is only a wake-up accelerator, so this
                    # bounded scan also drains rows beyond the startup page.
                    self._resume_queued_relay_events()
                    self.reconcile_relay_operations()
                    self.reconcile_receipts()
                    last_recovery_scan = now
                except Exception as error:
                    if not self._closing:
                        logger.warning("Loopdy background reconciliation failed: %s", _safe_error(error))
                continue
            try:
                if item is None:
                    return
                event, target = item
                try:
                    self.deliver(event, target=target)
                except Exception as error:
                    # A malformed or otherwise unexpected event must not
                    # kill the sole durable recovery owner.  Delivery errors
                    # are persisted by deliver where possible; this catch is
                    # the final containment boundary for worker continuity.
                    logger.warning(
                        "Loopdy queued delivery failed: %s", _safe_error(error)
                    )
            finally:
                self._queue.task_done()

    def _reconcile_live_activity_updates(self) -> None:
        pending = self.store.due_live_activity_updates(limit=100)
        if not pending:
            return
        for item in pending:
            activity_id = str(item["activity_id"])
            try:
                with self.store.live_activity_send_lock(activity_id):
                    activity = self.store.active_live_activity(activity_id)
                    current = self.store.pending_live_activity_update(activity_id)
                    if activity is None or current is None:
                        continue
                    try:
                        self._send_live_activity_update(
                            activity,
                            status=str(current["status"]),
                            detail=str(current["detail"]),
                            tool_name=str(current["tool_name"]),
                            active_session_count=int(current["active_session_count"]),
                        )
                        if str(current["status"]) in {"completed", "failed"}:
                            self.store.end_live_activity(
                                activity_id,
                                expected_session_id=str(activity["session_id"]),
                                expected_live_session_id=str(activity["live_session_id"]),
                                expected_profile=str(activity["profile"]),
                                expected_push_token=str(activity["push_token"]),
                                expected_owner_generation=int(activity.get("owner_generation") or 0),
                                expected_request_id=str(current.get("request_id") or ""),
                            )
                        else:
                            self.store.clear_pending_live_activity_update(
                                activity_id,
                                expected_session_id=str(activity["session_id"]),
                                expected_live_session_id=str(activity["live_session_id"]),
                                expected_profile=str(activity["profile"]),
                                expected_push_token=str(activity["push_token"]),
                                expected_owner_generation=int(activity.get("owner_generation") or 0),
                                expected_request_id=str(current.get("request_id") or ""),
                            )
                    except Exception as error:
                        if isinstance(error, DeliveryError) and error.invalid_token:
                            self.store.end_live_activity(
                                activity_id,
                                expected_session_id=str(activity["session_id"]),
                                expected_live_session_id=str(activity["live_session_id"]),
                                expected_profile=str(activity["profile"]),
                                expected_push_token=str(activity["push_token"]),
                                expected_owner_generation=int(activity.get("owner_generation") or 0),
                                expected_request_id=str(current.get("request_id") or ""),
                            )
                            continue
                        if isinstance(error, DeliveryError) and error.retryable:
                            attempts = max(1, int(current["attempts"]))
                            self.store.defer_live_activity_update(
                                activity_id=activity_id,
                                status=str(current["status"]),
                                detail=str(current["detail"]),
                                tool_name=str(current["tool_name"]),
                                active_session_count=int(current["active_session_count"]),
                                delay_seconds=min(300, 2 ** min(8, attempts)),
                                failure=_safe_error(error),
                                expected_session_id=str(activity["session_id"]),
                                expected_live_session_id=str(activity["live_session_id"]),
                                expected_profile=str(activity["profile"]),
                                expected_push_token=str(activity["push_token"]),
                                expected_owner_generation=int(activity.get("owner_generation") or 0),
                                expected_request_id=str(current.get("request_id") or ""),
                            )
                        else:
                            self.store.clear_pending_live_activity_update(
                                activity_id,
                                expected_session_id=str(activity["session_id"]),
                                expected_live_session_id=str(activity["live_session_id"]),
                                expected_profile=str(activity["profile"]),
                                expected_push_token=str(activity["push_token"]),
                                expected_owner_generation=int(activity.get("owner_generation") or 0),
                                expected_request_id=str(current.get("request_id") or ""),
                            )
            except Exception as error:
                logger.warning(
                    "Loopdy deferred Live Activity serialization failed for %s: %s",
                    activity_id,
                    _safe_error(error),
                )

    def _reconcile_relay_live_activity_updates(self) -> None:
        pending = self.store.due_relay_live_activity_updates(limit=100)
        for item in pending:
            activity_id = str(item["activity_id"])
            try:
                with self.store.live_activity_send_lock(activity_id):
                    current_pending = self.store.pending_relay_live_activity_update(activity_id)
                    if current_pending is None or any(
                        str(current_pending.get(key) or "") != str(item.get(key) or "")
                        for key in ("device_id", "session_ref", "revision", "lease_expires", "relay_generation", "delivery_id", "idempotency_key")
                        if item.get(key) not in (None, "", 0)
                    ):
                        continue
                    item = current_pending
                    # The due-list snapshot was taken before the per-activity
                    # lock.  Another owner may have deferred this exact row
                    # while we waited, so re-check the durable schedule after
                    # acquiring the lock before sending.
                    if int(item.get("terminal") or 0) or int(item.get("next_attempt_at") or 0) > int(time.time()):
                        continue
                    activity = self.store.active_relay_live_activity(
                        activity_id,
                        expected_session_ref=str(item["session_ref"]),
                        expected_device_id=str(item["device_id"]),
                        expected_revision=int(item["revision"]),
                        expected_lease_expires=int(item["lease_expires"]),
                    )
                    if activity is None:
                        self._clear_relay_pending(item, item)
                        continue
                    activity = {**activity, "delivery_provider": "relay"}
                    relay_request = self._prepare_relay_live_activity_request(
                        activity,
                        status=str(item["status"]),
                        active_session_count=int(item["active_session_count"]),
                        pending=item,
                    )
                    if not str(item.get("request_body_json") or ""):
                        self.store.defer_relay_live_activity_update(
                            activity_id=activity_id,
                            status=str(item["status"]),
                            detail=str(item["detail"]),
                            tool_name=str(item["tool_name"]),
                            active_session_count=int(item["active_session_count"]),
                            delay_seconds=0,
                            failure=str(item.get("last_error") or ""),
                            timestamp=int(relay_request["timestamp"]),
                            delivery_id=str(relay_request["delivery_id"]),
                            idempotency_key=str(relay_request["idempotency_key"]),
                            request_body=relay_request["request_body"],
                            **self._relay_activity_owner(activity),
                        )
                        refreshed = self.store.pending_relay_live_activity_update(activity_id)
                        if refreshed is None or not all(
                            str(refreshed.get(key) or "")
                            for key in ("request_body_json", "delivery_id", "idempotency_key")
                        ):
                            continue
                        item = refreshed
                        relay_request = self._prepare_relay_live_activity_request(
                            activity,
                            status=str(item["status"]),
                            active_session_count=int(item["active_session_count"]),
                            pending=item,
                        )
                    try:
                        self._send_live_activity_update(
                            activity,
                            status=str(item["status"]),
                            detail=str(item["detail"]),
                            tool_name=str(item["tool_name"]),
                            active_session_count=int(item["active_session_count"]),
                            relay_request=relay_request,
                        )
                        if str(item["status"]) in {"completed", "failed"}:
                            self.store.end_relay_live_activity(
                                activity_id,
                                expected_session_ref=str(activity["session_ref"]),
                                expected_device_id=str(activity["device_id"]),
                                expected_revision=int(activity["revision"]),
                                expected_delivery_id=str(item["delivery_id"]),
                                expected_idempotency_key=str(item["idempotency_key"]),
                            )
                        else:
                            self._clear_relay_pending(activity, item)
                    except Exception as error:
                        if isinstance(error, DeliveryError) and error.invalid_token:
                            self.store.end_relay_live_activity(
                                activity_id,
                                expected_session_ref=str(activity["session_ref"]),
                                expected_device_id=str(activity["device_id"]),
                                expected_revision=int(activity["revision"]),
                                expected_delivery_id=str(item["delivery_id"]),
                                expected_idempotency_key=str(item["idempotency_key"]),
                            )
                        elif isinstance(error, RelayOutcomeUnknown) or (
                            isinstance(error, DeliveryError) and error.retryable
                        ):
                            attempts = max(1, int(item["attempts"]))
                            self.store.defer_relay_live_activity_update(
                                activity_id=activity_id,
                                status=str(item["status"]),
                                detail=str(item["detail"]),
                                tool_name=str(item["tool_name"]),
                                active_session_count=int(item["active_session_count"]),
                                delay_seconds=min(300, 2 ** min(8, attempts)),
                                failure=_safe_error(error),
                                expected_device_id=str(item["device_id"]),
                                expected_session_ref=str(item["session_ref"]),
                                expected_revision=int(item["revision"]),
                                expected_lease_expires=int(item["lease_expires"]),
                                expected_relay_generation=int(item.get("relay_generation") or 0),
                                expected_delivery_id=str(item["delivery_id"]),
                                expected_idempotency_key=str(item["idempotency_key"]),
                            )
                        else:
                            self._clear_relay_pending(activity, item)
                            logger.warning(
                                "Loopdy relay Live Activity update failed for %s: %s",
                                activity_id,
                                _safe_error(error),
                            )
            except Exception as error:
                if isinstance(error, ValueError):
                    self._clear_relay_pending(item, item)
                logger.warning(
                    "Loopdy deferred relay Live Activity serialization failed for %s: %s",
                    activity_id,
                    _safe_error(error),
                )

    def _run_live_activity_worker(self) -> None:
        while True:
            try:
                item = self._live_activity_queue.get(timeout=0.25)
            except queue.Empty:
                if self._closed:
                    return
                self._reconcile_live_activity_updates()
                self._reconcile_relay_live_activity_updates()
                continue
            try:
                if item is None:
                    return
                try:
                    self.update_live_activities(**item)
                except Exception as error:
                    logger.warning(
                        "Loopdy Live Activity update skipped: %s",
                        _safe_error(error),
                    )
            finally:
                self._live_activity_queue.task_done()


def _safe_error(error: Exception) -> str:
    if isinstance(error, DeliveryError):
        return f"Push provider error {error.status}: {error.code}"
    if isinstance(error, ValueError):
        return str(error)[:500]
    return f"Loopdy delivery failed: {type(error).__name__}"


def _relay_operation_name(value: Any) -> str:
    normalized = str(value or "").strip()
    return "revoke_device" if normalized == "device_revoke" else normalized


def _can_resume_relay_registration(
    stored: Mapping[str, Any], operation: str, submitted: Mapping[str, Any]
) -> bool:
    """Allow only a newer retry for the exact same registration target.

    The durable request remains authoritative.  This predicate deliberately
    excludes the mutable lease/timestamp/revision/idempotency coordinates and
    requires every device-routing and encryption input to match exactly.
    """
    if operation != "register_device":
        return False
    try:
        stored_revision = stored["revision"]
        submitted_revision = submitted["revision"]
    except KeyError:
        return False
    if (
        type(stored_revision) is not int
        or type(submitted_revision) is not int
        or submitted_revision <= stored_revision
    ):
        return False
    return all(
        field in stored
        and field in submitted
        and type(stored[field]) is type(submitted[field])
        and stored[field] == submitted[field]
        for field in _RELAY_REGISTRATION_SCOPE_FIELDS
    )


def _request_digest(value: Mapping[str, Any]) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _decode_relay_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid relay base64url value")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (TypeError, ValueError, binascii.Error) as error:
        raise ValueError("Invalid relay base64url value") from error


def _live_activity_phase(value: Any) -> str:
    normalized = str(value or "").strip()
    mapping = {
        "reasoning": "thinking",
        "needsResponse": "waiting",
        "runningCommand": "running",
        "callingTool": "running",
        "replying": "running",
    }
    phase = mapping.get(normalized, normalized)
    if phase not in {"thinking", "waiting", "running", "completed", "failed"}:
        raise ValueError("Live Activity phase is invalid")
    return phase


def _session_reference(value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _suppression_reason(event: LoopdyEvent, preferences: Mapping[str, Any], now: Any) -> str:
    if preferences.get("notifications_enabled") is False:
        return "notifications_disabled"
    enabled_types = preferences.get("enabled_types")
    if isinstance(enabled_types, list) and event.type not in enabled_types:
        return "event_type_disabled"
    quiet_hours = preferences.get("quiet_hours")
    if isinstance(quiet_hours, Mapping) and _in_quiet_hours(
        quiet_hours,
        now,
        preferences.get("timezone"),
    ):
        return "quiet_hours"
    return ""


def _in_quiet_hours(
    quiet_hours: Mapping[str, Any],
    now: Any,
    timezone_name: Any = None,
) -> bool:
    start = _clock_minutes(quiet_hours.get("start"))
    end = _clock_minutes(quiet_hours.get("end"))
    if start is None or end is None or start == end:
        return False
    zone = None
    if str(timezone_name or "").strip():
        try:
            zone = ZoneInfo(str(timezone_name).strip())
        except ZoneInfoNotFoundError:
            zone = None
    if isinstance(now, datetime):
        current = now
        if zone is not None:
            current = current.astimezone(zone) if current.tzinfo else current.replace(tzinfo=zone)
    else:
        current = (
            datetime.fromtimestamp(float(now), tz=zone)
            if zone is not None
            else datetime.fromtimestamp(float(now)).astimezone()
        )
    minute = current.hour * 60 + current.minute
    if start < end:
        return start <= minute < end
    return minute >= start or minute < end


def _clock_minutes(value: Any) -> int | None:
    text = str(value or "")
    parts = text.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    hour, minute = (int(part) for part in parts)
    if hour > 23 or minute > 59:
        return None
    return hour * 60 + minute


def _validate_endpoint(provider: str, endpoint_id: str) -> None:
    value = str(endpoint_id or "").strip()
    if provider == "managed":
        if not (
            value.startswith("ExponentPushToken[") or value.startswith("ExpoPushToken[")
        ) or not value.endswith("]"):
            raise ValueError("Managed devices require an Expo push token")
    elif provider == "direct":
        if len(value) < 64 or len(value) > 200 or any(character not in "0123456789abcdefABCDEF" for character in value):
            raise ValueError("Direct devices require a native APNs token")
    else:
        raise ValueError("Loopdy device provider must be managed or direct")


def _validate_device_routing(device_id: str, groups: list[str]) -> None:
    verdict = validate_target(f"device:{device_id}")
    if verdict is not True:
        raise ValueError(f"Invalid Loopdy device ID: {verdict}")
    for group in groups:
        verdict = validate_target(f"group:{group}")
        if verdict is not True:
            raise ValueError(f"Invalid Loopdy group ID: {verdict}")
