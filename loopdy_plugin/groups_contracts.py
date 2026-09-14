"""Bounded hosted-room wire validation, never room execution or storage."""
from __future__ import annotations

import json
import math
import re
from typing import Any


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KIND = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
GROUPS_RESULTS_CAPABILITY = "groups-results-v1"
GROUPS_RESULT_PAYLOAD_BYTES = 2 * 1024 * 1024
GROUPS_RESULT_ENVELOPE_BYTES = GROUPS_RESULT_PAYLOAD_BYTES + 4096
GROUPS_RESULT_OPERATIONS = frozenset({
    "groups.capabilities", "groups.list", "groups.create", "groups.state",
    "groups.send", "groups.rename", "groups.log", "groups.stop", "groups.retry", "groups.approve",
})


def validate_result_version(value: Any, operation: str) -> int:
    if type(value) is not int or value != 1 or operation not in GROUPS_RESULT_OPERATIONS:
        raise ValueError("Loopdy groups result negotiation is invalid")
    return value


def _integer(value: Any, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9_007_199_254_740_991:
        raise ValueError("Hermes room integer is invalid")
    return value


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError("Hermes room coordinate is invalid")
    return value


def validate_log_page(payload: Any, request: dict[str, Any]) -> None:
    """Validate the only location where groups.log permits a gateway_id key."""
    if not isinstance(payload, dict) or set(payload) != {
        "events", "cursor", "latest_seq", "has_more", "authority"
    }:
        raise ValueError("Hermes room log fields are invalid")
    room_id = _identifier(request.get("room_id"))
    sequence = _integer(request.get("since_seq", 0))
    limit = _integer(request.get("limit", 100), minimum=1)
    if limit > 500:
        raise ValueError("Hermes room log limit is invalid")
    authority = payload["authority"]
    if not isinstance(authority, dict) or set(authority) != {"gateway_id", "epoch"}:
        raise ValueError("Hermes room authority is invalid")
    _identifier(authority["gateway_id"])
    epoch = _integer(authority["epoch"], minimum=1)
    cursor = _integer(payload["cursor"])
    latest = _integer(payload["latest_seq"])
    if (type(payload["has_more"]) is not bool or not sequence <= cursor <= latest
            or payload["has_more"] != (cursor < latest)):
        raise ValueError("Hermes room cursor is invalid")
    events = payload["events"]
    if not isinstance(events, list) or len(events) > limit:
        raise ValueError("Hermes room events are invalid")
    event_ids: set[str] = set()
    required = {"room_id", "seq", "event_id", "kind", "actor", "payload", "created_at"}
    optional = {"authority_epoch", "idempotent"}
    for event in events:
        if not isinstance(event, dict) or not required <= set(event) <= required | optional:
            raise ValueError("Hermes room event fields are invalid")
        if event["room_id"] != room_id or _integer(event["seq"], minimum=1) != sequence + 1:
            raise ValueError("Hermes room event sequence is invalid")
        sequence += 1
        event_id = _identifier(event["event_id"])
        if event_id in event_ids:
            raise ValueError("Hermes room event identity is duplicated")
        event_ids.add(event_id)
        if not isinstance(event["kind"], str) or _KIND.fullmatch(event["kind"]) is None:
            raise ValueError("Hermes room event kind is invalid")
        actor = event["actor"]
        if (not isinstance(actor, dict) or not {"kind", "id"} <= set(actor)
                or set(actor) - {"kind", "id", "display_name", "profile", "connection_id"}
                or actor["kind"] not in {"user", "member", "gateway", "system"}):
            raise ValueError("Hermes room actor is invalid")
        _identifier(actor["id"])
        for key in ("profile", "connection_id"):
            if key in actor:
                _identifier(actor[key])
        if "display_name" in actor:
            name = actor["display_name"]
            if not isinstance(name, str) or not 1 <= len(name) <= 200:
                raise ValueError("Hermes room actor label is invalid")
        if ((event["kind"] == "message.user" and actor["kind"] != "user")
                or (event["kind"] == "message.member" and actor["kind"] != "member")):
            raise ValueError("Hermes room message actor is invalid")
        event_epoch = event.get("authority_epoch")
        if event_epoch is not None and _integer(event_epoch, minimum=1) > epoch:
            raise ValueError("Hermes room event authority is invalid")
        if "idempotent" in event and type(event["idempotent"]) is not bool:
            raise ValueError("Hermes room event idempotency is invalid")
        timestamp = event["created_at"]
        if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
                or not 0 <= timestamp <= 253_402_300_799):
            raise ValueError("Hermes room event timestamp is invalid")
        if not isinstance(event["payload"], dict):
            raise ValueError("Hermes room event payload is invalid")
        if len(json.dumps(event["payload"], ensure_ascii=False, separators=(",", ":")).encode()) > 256 * 1024:
            raise ValueError("Hermes room event payload is too large")
    if cursor != sequence or (payload["has_more"] and not events):
        raise ValueError("Hermes room cursor did not consume the returned events")
