"""Request-bound Loopdy approval transport."""

from __future__ import annotations

import math
import time
from typing import Any

from .events import build_event
from .store import LoopdyStore


class LoopdyApprovalTransport:
    def __init__(
        self,
        store: LoopdyStore,
        service: Any,
        *,
        target: str = "all",
        profile: str = "default",
        agent_name: str = "",
        poll_interval: float = 0.25,
    ):
        self.store = store
        self.service = service
        self.target = target
        self.profile = profile
        self.agent_name = " ".join(agent_name.split())[:80]
        self.poll_interval = max(0.001, float(poll_interval))

    def present(self, request: Any):
        timeout = max(0.0, float(request.timeout_seconds))
        expires_at = math.ceil(time.time() + timeout)
        deadline = time.monotonic() + timeout
        allowed_choices = [
            choice
            for choice in ("once", "session", "always", "deny")
            if choice in request.allowed_choices
        ]
        if not allowed_choices:
            return request.respond("deny")
        event = build_event(
            "approval.required",
            correlation=("approval", request.request_id, request.digest),
            profile=self.profile,
            approval_id=str(request.request_id),
            detail={
                "command": str(request.command),
                "description": str(request.description),
                "pattern_key": str(request.pattern_key),
                "pattern_keys": list(request.pattern_keys),
                "surface": str(request.surface),
                "allowed_choices": allowed_choices,
                "expires_at": expires_at,
                "interaction": {
                    "schemaVersion": 1,
                    "type": "approval",
                    "requestId": str(request.request_id),
                    "expiresAt": expires_at,
                    "allowedChoices": allowed_choices,
                },
                **({"agent_name": self.agent_name} if self.agent_name else {}),
            },
        )
        self.store.create_approval(
            approval_id=str(request.request_id),
            request_digest=str(request.digest),
            allowed_choices=allowed_choices,
            event_id=event.event_id,
            expires_at=expires_at,
        )
        delivery = self.service.deliver(event, target=self.target)
        if not delivery.get("success"):
            return request.respond("deny")

        while time.monotonic() < deadline:
            record = self.store.get_approval(str(request.request_id))
            if record is None or record["status"] == "expired":
                break
            if record["status"] == "responded":
                return request.respond(record["choice"])
            time.sleep(min(self.poll_interval, max(0.0, deadline - time.monotonic())))
        return request.respond("deny")
