"""Bounded client for managed delivery through Expo Push Service."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable

from ..provider import (
    DeliveryError,
    DeliveryReceipt,
    ProviderReceipt,
    PushMessage,
)


_SEND_URL = "https://exp.host/--/api/v2/push/send"
_RECEIPTS_URL = "https://exp.host/--/api/v2/push/getReceipts"
_TOKEN = re.compile(r"^(?:Exponent|Expo)PushToken\[[A-Za-z0-9._~-]{8,200}\]$")
_REVIEW_EVENTS = frozenset({"attention.required", "approval.required"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ExpoPushProvider:
    name = "managed"

    def __init__(self, *, open_request: Callable[..., Any] | None = None):
        self._open_request = open_request or _default_open_request

    def send(
        self,
        token: str,
        message: PushMessage,
        *,
        environment: str = "",
    ) -> DeliveryReceipt:
        normalized_token = str(token or "").strip()
        if not _TOKEN.fullmatch(normalized_token):
            raise ValueError("A valid Expo push token is required")
        payload: dict[str, Any] = {
            "to": normalized_token,
            "title": message.title,
            "body": message.body,
            "data": dict(message.data),
            "priority": "high" if message.sound else "normal",
        }
        if message.sound:
            payload["sound"] = "default"
        if message.event_type == "channel.message":
            payload["badge"] = 1
        if message.event_type in _REVIEW_EVENTS:
            # Managed delivery keeps the established category for installed-client compatibility.
            # Current Loopdy builds register this alias with the authenticated Review action.
            payload["categoryId"] = "LOOPDY_APPROVAL"
        result = self._request_json(_SEND_URL, payload)
        ticket = result.get("data")
        if isinstance(ticket, list):
            ticket = ticket[0] if len(ticket) == 1 else None
        if not isinstance(ticket, dict):
            raise DeliveryError("invalid_ticket_response", retryable=True)
        if ticket.get("status") != "ok":
            raise _provider_error(ticket)
        ticket_id = _identifier(ticket.get("id"), "ticket")
        return DeliveryReceipt(delivery_id=ticket_id, pending_receipt_id=ticket_id)

    def receipts(self, receipt_ids: Iterable[str]) -> dict[str, ProviderReceipt]:
        ids = [_identifier(value, "receipt") for value in receipt_ids]
        if not ids or len(ids) > 1000:
            raise ValueError("Expo receipt queries require between 1 and 1000 IDs")
        result = self._request_json(_RECEIPTS_URL, {"ids": ids})
        raw_receipts = result.get("data")
        if not isinstance(raw_receipts, dict):
            raise DeliveryError("invalid_receipt_response", retryable=True)
        receipts: dict[str, ProviderReceipt] = {}
        for receipt_id in ids:
            raw = raw_receipts.get(receipt_id)
            if not isinstance(raw, dict):
                continue
            if raw.get("status") == "ok":
                receipts[receipt_id] = ProviderReceipt(status="delivered")
                continue
            error = _provider_error(raw)
            receipts[receipt_id] = ProviderReceipt(
                status="failed",
                error_code=error.code,
                invalid_token=error.invalid_token,
                retryable=error.retryable,
            )
        return receipts

    def _request_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "Loopdy-Hermes-Plugin/2.0",
            },
            method="POST",
        )
        try:
            with self._open_request(request, timeout=8) as response:
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise DeliveryError("oversized_response", retryable=False)
                value = json.loads(raw) if raw else {}
                if not isinstance(value, dict):
                    raise DeliveryError("invalid_response", retryable=True)
                return value
        except urllib.error.HTTPError as error:
            try:
                code = _http_error_code(error)
            finally:
                error.close()
            raise DeliveryError(code, status=error.code) from error
        except DeliveryError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise DeliveryError("transport_error", retryable=True) from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DeliveryError("invalid_response", retryable=True) from error


def _provider_error(value: dict[str, Any]) -> DeliveryError:
    details = value.get("details")
    code = details.get("error") if isinstance(details, dict) else None
    normalized = str(code or value.get("message") or "request_rejected").strip()[:80]
    invalid = normalized == "DeviceNotRegistered"
    retryable = normalized == "MessageRateExceeded"
    return DeliveryError(
        normalized,
        status=429 if retryable else 400,
        invalid_token=invalid,
        retryable=retryable,
    )


def _http_error_code(error: urllib.error.HTTPError) -> str:
    try:
        value = json.loads(error.read(4096))
        errors = value.get("errors") if isinstance(value, dict) else None
        first = errors[0] if isinstance(errors, list) and errors else None
        code = first.get("code") if isinstance(first, dict) else None
        if isinstance(code, str) and code:
            return code[:80]
    except Exception:
        pass
    return "request_rejected"


def _identifier(value: Any, name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 180:
        raise DeliveryError(f"invalid_{name}_response", retryable=True)
    return normalized


def _default_open_request(request: urllib.request.Request, *, timeout: int):
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


__all__ = ["ExpoPushProvider"]
