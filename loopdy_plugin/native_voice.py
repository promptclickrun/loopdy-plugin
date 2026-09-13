"""Native authenticated media only. Hermes owns every delegated chat turn.

This bounded, disposable feed replaces Link's voice control channel. It does not
execute prompts, store transcripts, own jobs, or implement a second scheduler.
The native app submits work through ordinary Hermes prompt.submit and appends
the resulting answer here. Provider credentials never leave this process.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import os
import time
from typing import Literal

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .native_context import NativeAPIError, NativeContext, native_context
from .live_voice_provider import make_live_provider, validate_audio_sdp

CAPABILITY = "native-voice-v1"


def _reject(code="voice_unavailable", status=409):
    return NativeAPIError(status, code, "This native voice operation is unavailable. Reconnect explicitly when ready.")


@dataclass
class _Call:
    owner: NativeContext
    profile: str
    session: str
    provider: object = None
    closed: bool = False
    sequence: int = 0
    events: list = field(default_factory=list)
    delegations: dict = field(default_factory=dict)
    appended: set = field(default_factory=set)
    lease: float = 0
    watch: asyncio.Task | None = None


class NativeVoiceHub:
    def __init__(self, *, provider_factory=make_live_provider, lease_seconds=60):
        self.factory = provider_factory
        self.lease_seconds = lease_seconds
        self.calls: dict[str, _Call] = {}

    def _claim(self, owner, fields):
        identifier = fields["voiceId"]
        if identifier in self.calls or len(self.calls) >= 1024:
            raise _reject("voice_id_consumed")
        call = _Call(owner, fields["agentId"], fields["sessionId"], lease=time.monotonic())
        self.calls[identifier] = call  # Before any suspension/provider allocation.
        return call

    def _owned(self, owner, fields):
        call = self.calls.get(fields["voiceId"])
        if call is None or (call.owner, call.profile, call.session) != (owner, fields["agentId"], fields["sessionId"]):
            raise _reject("voice_owner_changed")
        return call

    async def offer(self, owner, fields):
        validate_audio_sdp(fields["sdp"])
        if sum(not call.closed for call in self.calls.values()) >= 4:
            raise _reject("voice_capacity", 503)
        if any(not call.closed and call.owner == owner for call in self.calls.values()):
            raise _reject("voice_already_active")
        call = self._claim(owner, fields)
        try:
            kwargs = {"mode": fields["provider"], "on_event": lambda event: self._event(call, event)}
            if fields["provider"] == "api_key":
                kwargs["api_key"] = lambda: os.environ.get("OPENAI_API_KEY", "")
            call.provider = self.factory(**kwargs)
            call.watch = asyncio.create_task(self._watch(call))
            async with asyncio.timeout(40):
                answer = await call.provider.create(fields["sdp"], voice=fields["voice"])
            if call.closed:
                raise _reject("voice_closed_during_setup")
            validate_audio_sdp(answer)
            if len(answer.encode("utf-8")) > 180_000:
                raise _reject("voice_answer_too_large")
            return {"voiceId": fields["voiceId"], "sdp": answer}
        except BaseException:
            await self._close(call)
            raise

    async def _event(self, call, event):
        if call.closed or not isinstance(event, dict):
            return
        kind = event.get("kind")
        if kind not in {"started", "sideband_attached", "transcript_delta", "transcript_done", "delegation",
                        "delegation_context_required", "provider_error", "transport_closed", "session_closed", "audio_cleared"}:
            return
        encoded = json.dumps(event, allow_nan=False).encode("utf-8")
        if len(encoded) > 32_768 or len(call.events) >= 128 or sum(len(row[2]) for row in call.events) + len(encoded) > 524_288:
            await self._close(call)
            return
        if kind in {"delegation", "delegation_context_required"}:
            identifier = event.get("id")
            if not isinstance(identifier, str) or not identifier or len(identifier.encode("utf-8")) > 180:
                await self._close(call)
                return
            previous = call.delegations.get(identifier)
            if previous is not None:
                if previous != event:
                    await self._close(call)
                return  # A provider retransmission never submits another turn.
            if len(call.delegations) >= 1024:
                await self._close(call)
                return
            call.delegations[identifier] = dict(event)
        call.sequence += 1
        call.events.append((call.sequence, event, encoded))
        if kind in {"transport_closed", "session_closed"} or (kind == "provider_error" and event.get("fatal") is not False):
            await self._close(call)

    def poll(self, owner, fields, *, after):
        call = self._owned(owner, fields)
        if after > call.sequence or (call.events and after < call.events[0][0] - 1):
            raise _reject("voice_feed_gap")
        call.events = [row for row in call.events if row[0] > after]
        call.lease = time.monotonic()
        rows = call.events[:4]  # At most 128 KiB plus the envelope.
        return {"voiceId": fields["voiceId"], "closed": call.closed,
                "next": rows[-1][0] if rows else after,
                "events": [{"sequence": sequence, "event": event} for sequence, event, _ in rows]}

    async def result(self, owner, fields):
        call = self._owned(owner, fields)
        identifier = fields["delegationId"]
        if call.closed or identifier not in call.delegations or identifier in call.appended:
            raise _reject("voice_result_unavailable")
        call.appended.add(identifier)  # A lost provider receipt never permits replay.
        await call.provider.append_result(identifier, fields["text"])
        return {"voiceId": fields["voiceId"], "appended": True}

    async def close(self, owner, fields):
        call = self._owned(owner, fields) if fields["voiceId"] in self.calls else self._claim(owner, fields)
        await self._close(call)
        return {"voiceId": fields["voiceId"], "closed": True}

    async def _close(self, call):
        if call.closed:
            return
        call.closed = True
        call.events.clear()
        call.delegations.clear()
        call.appended.clear()
        if call.watch and call.watch is not asyncio.current_task():
            call.watch.cancel()
        provider, call.provider = call.provider, None
        if provider:
            try:
                async with asyncio.timeout(5):
                    await provider.close()
            except Exception:
                pass  # Media is locally retired; never create a replacement.

    async def _watch(self, call):
        while not call.closed:
            await asyncio.sleep(self.lease_seconds)
            if time.monotonic() - call.lease >= self.lease_seconds:
                await self._close(call)

    async def shutdown(self):
        for call in self.calls.values():
            await self._close(call)


_HUB = NativeVoiceHub()


class _Scope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    sessionId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$")


class _Status(_Scope):
    provider: Literal["codex_subscription", "api_key"]


class _Voice(_Scope):
    voiceId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$")


class _Offer(_Voice):
    provider: Literal["codex_subscription", "api_key"]
    voice: str = Field(min_length=1, max_length=32)
    sdp: str = Field(min_length=1, max_length=180_000)


class _Poll(_Voice):
    after: StrictInt = Field(ge=0, le=9_007_199_254_740_991)


class _Result(_Voice):
    delegationId: str = Field(min_length=1, max_length=180)
    text: str = Field(min_length=1, max_length=1500)


async def request(operation: str, request: Request):
    from .native_api import _body, _precondition, _response
    models = {"status": _Status, "offer": _Offer, "poll": _Poll, "result": _Result, "close": _Voice}
    if operation not in models:
        raise _reject("unknown_voice_operation", 404)
    owner = native_context(request)
    request_id = _precondition(request, owner)
    body = await _body(request, models[operation])
    fields = body.model_dump()
    from hermes_cli.profiles import profile_exists
    from hermes_constants import get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override
    token = set_hermes_home_override(get_process_hermes_home())
    try:
        if not profile_exists(body.agentId):
            raise _reject("profile_not_found", 404)
    finally:
        reset_hermes_home_override(token)
    if native_context(request) != owner:
        raise _reject("context_changed", 412)
    if operation == "status":
        configured = body.provider == "codex_subscription" or bool(os.environ.get("OPENAI_API_KEY"))
        value = {"available": configured, "enabled": True, "provider": body.provider, "interruptSupported": False}
    elif operation == "poll":
        value = _HUB.poll(owner, fields, after=body.after)
    else:
        value = await getattr(_HUB, operation)(owner, fields)
    if native_context(request) != owner:
        if operation == "offer":
            await _HUB.close(owner, fields)
        raise _reject("context_changed", 412)
    return _response(value, owner, request_id)
