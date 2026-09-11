"""Authenticated Live voice composition; media never owns delegated Hermes jobs.

Imports and construction are inert. Provider authentication happens only after a
persisted, one-use offer claim. All execution uses the adapter's ordinary ingress
and its supported processing/approval/clarification callbacks.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inbound_dispatch import ReplyRoute, current_reply_route, current_turn_lease
from .link_client import InboundLinkTurn
from .link_contracts import UserMessage, WorkspaceRequest
from .voice_jobs import VoiceJobLedger, VoiceJobOrchestrator, VoiceJobOwner, VoiceJobError
from .wiki_transport import authority_id

OPERATIONS = frozenset({"voice.live.status", "voice.live.offer", "voice.live.close",
                        "voice.live.jobs", "voice.live.control"})
_ID = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.:-]{0,179}\Z")
_TERMINAL = {"completed", "failed", "cancelled", "expired"}


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid live voice coordinate")
    return value


def _safe_text(value, maximum=1600):
    """Only assistant-final/prompt text enters here, never tools or reasoning."""
    if not isinstance(value, str):
        return ""
    try:
        from agent.redact import redact_sensitive_text
        value = redact_sensitive_text(value, force=True)
    except Exception:
        return ""  # A missing redactor must not become a raw-text fallback.
    if re.search(r"💭|^.*(?:Reasoning|Thinking):|^(?:>|-#) ", value, re.M | re.I):
        return ""
    value = re.sub(r"```.*?```", "", value, flags=re.S)
    value = re.sub(r"<(?:think|analysis|reasoning)>.*?</(?:think|analysis|reasoning)>", "", value, flags=re.S | re.I)
    value = " ".join(value.split())
    # Never speak paths, URLs, credential-shaped tokens or serialized objects.
    if re.search(r"https?://|(?:/Users/|/home/)|\b(?:Bearer|password|api[_ -]?key|secret)\b|[A-Za-z0-9_=-]{48,}|[{}]", value, re.I):
        return ""
    if len(value.encode("utf-16-le")) > maximum * 2 or len(value.encode("utf-8")) > 3500:
        return ""  # Do not truncate a fact into a different assertion.
    return value


def project_job(job):
    result = {"jobId": job.job_id, "sessionId": job.session_id, "runId": job.run_id,
              "revision": job.revision, "state": job.state}
    if job.summary:
        result["summary"] = job.summary
    if job.pending:
        result["pending"] = {"pendingId": job.pending.pending_id, "revision": job.pending.revision,
                             "kind": job.pending.kind, "prompt": job.pending.prompt}
    return result


@dataclass
class _Call:
    voice_id: str
    owner: VoiceJobOwner
    session_id: str
    route: ReplyRoute
    mode: str
    provider: Any = None
    setup: asyncio.Task | None = None
    closed: bool = False
    ready: bool = False
    results: dict = field(default_factory=dict)
    appended: set = field(default_factory=set)
    transcripts: list = field(default_factory=list)
    close_task: asyncio.Task | None = None
    last_probe: float = 0.0
    delegation_briefs: dict = field(default_factory=dict)
    context_offset: int = -1
    context_incomplete: bool = False


@dataclass
class _JobBinding:
    job: Any
    route: ReplyRoute
    turns: dict = field(default_factory=dict)
    routes: dict = field(default_factory=dict)
    finals: dict = field(default_factory=dict)
    outcomes: dict = field(default_factory=dict)
    session_keys: set = field(default_factory=set)
    pending_resolver: Any = None


class LiveVoiceRuntime:
    def __init__(self, adapter, *, storage_root: Path, provider_factory=None, settings_getter=None):
        self.adapter = adapter
        self.root = Path(storage_root)
        self.provider_factory = provider_factory
        self.settings_getter = settings_getter
        self.calls = {}
        self.bindings = {}
        self._ledger = None
        self.jobs = None
        self._offers = None
        self._offer_identity = None
        self._offer_path = None
        self._authority = None
        self._origin = None
        self._owners = {}
        self._tasks = set()
        self._controls = {}
        self._approvals = {}
        self._approval_futures = set()
        self._closed = False
        self._loop = None
        self._watch_task = None
        self._auth_states = {}

    def _settings(self):
        values = self.settings_getter() if self.settings_getter else {}
        if not isinstance(values, dict):
            raise ValueError("Invalid live voice settings")
        return values

    def _api_key(self):
        # OPENAI_API_KEY is the existing supported host environment path. No
        # phone key field, auth file, custom secret parser, or billing fallback.
        return os.environ.get("OPENAI_API_KEY", "")

    def _current(self, owner):
        if self._closed or owner not in self._owners:
            return False
        try:
            config = self.adapter._direct_current_config()
            return (authority_id(config) == self._authority and config.base_url == owner.account_origin
                    and config.device_id == owner.host_id and config.authorization_epoch == owner.host_epoch
                    and self._owners[owner] == self.adapter._transport_generation)
        except Exception:
            return False

    async def _scope(self, payload, route):
        if self._closed or not isinstance(route, ReplyRoute):
            raise ValueError("Live voice owner unavailable")
        route.check_current()
        if route.owner.transport == "link":
            from .link_contracts import DIRECTED_FRAMES_CAPABILITY
            if DIRECTED_FRAMES_CAPABILITY not in set(getattr(self.adapter.link_client, "peer_capabilities", ())):
                raise ValueError("Live voice requires directed Link responses")
        agent = _identifier(payload.get("agentId"))
        session = _identifier(payload.get("sessionId"))
        from .adapter import _is_link_chat_id
        if not _is_link_chat_id(session):
            raise ValueError("Invalid live conversation")
        config = self.adapter._direct_current_config()
        identity = authority_id(config)
        if route.owner.account_id != identity or route.owner.host_id != config.device_id or route.owner.host_epoch != config.authorization_epoch:
            raise ValueError("Live voice owner changed")
        if self._authority is not None and self._authority != identity:
            raise ValueError("Live voice pairing changed")
        known = self.adapter._link_session_profiles.get(session)
        if known is not None and known != agent:
            raise ValueError("Live voice profile changed")
        # Existing public workspace discovery is the profile access authority.
        catalog = await self.adapter.workspace_controller.execute(WorkspaceRequest(
            request_id="voice-profile-authorization", operation="agents.list", payload={}, sent_at=int(time.time())))
        if not any(isinstance(row, dict) and row.get("id") == agent for row in catalog.get("agents", ())):
            raise ValueError("Live voice profile unavailable")
        route.check_current()
        if authority_id(self.adapter._direct_current_config()) != identity:
            raise ValueError("Live voice pairing changed")
        owner = VoiceJobOwner(config.base_url, route.owner.host_id, route.owner.host_epoch,
                              route.owner.device_id, route.owner.device_epoch, agent)
        self._authority, self._origin = identity, config.base_url
        for prior in tuple(self._owners):
            if prior.device_id == owner.device_id and prior.device_epoch != owner.device_epoch:
                self._owners.pop(prior, None)
        if owner not in self._owners and len(self._owners) >= 1024:
            raise ValueError("Live owner capacity exhausted")
        self._owners[owner] = self.adapter._transport_generation
        self.adapter._remember_verified_link_profile(session, agent)
        self._loop = asyncio.get_running_loop()
        return owner, session

    def _storage(self):
        if self._ledger is not None:
            self._check_offer_storage()
            return
        if self._authority is None:
            raise ValueError("Live voice owner required")
        # Pairing identity includes the account-key digest. A re-pair can never
        # adopt the old account's ledger, even at the same service origin.
        directory = self.root / hashlib.sha256(self._authority.encode()).hexdigest()
        ledger = VoiceJobLedger(directory / "jobs.sqlite3")
        path = directory / "offers.sqlite3"
        offers = None
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise ValueError("Live offer storage unavailable")
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            self._offer_path = path
            self._offer_identity = (info.st_dev, info.st_ino)
            self._check_offer_storage()
            offers = sqlite3.connect(path)
            offers.execute("PRAGMA journal_mode=DELETE")
            offers.execute("PRAGMA synchronous=FULL")
            offers.execute("PRAGMA max_page_count=2048")
            offers.execute("CREATE TABLE IF NOT EXISTS offers (voice_id TEXT PRIMARY KEY, scope TEXT NOT NULL)")
            offers.commit()
        except BaseException:
            if offers is not None:
                offers.close()
            ledger.close()
            raise
        self._ledger, self._offers = ledger, offers
        self.jobs = VoiceJobOrchestrator(ledger, submit=self._submit, control=self._control, authorize=self._current)
        self._watch_task = asyncio.create_task(self._watch(), name="loopdy-live-lease")

    def _check_offer_storage(self):
        path = self._offer_path
        if path is None:
            raise ValueError("Live offer storage unavailable")
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = Path(str(path) + suffix)
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                if suffix:
                    continue
                raise ValueError("Live offer storage unavailable") from None
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
                    or (not suffix and (info.st_dev, info.st_ino) != self._offer_identity)):
                raise ValueError("Live offer storage changed")

    @staticmethod
    def _scope_key(owner, session):
        return json.dumps([owner.account_origin, owner.host_id, owner.host_epoch, owner.device_id,
                           owner.device_epoch, owner.agent_id, session], separators=(",", ":"))

    def _claim(self, voice_id, owner, session):
        self._check_offer_storage()
        key = self._scope_key(owner, session)
        if self._offers.execute("SELECT 1 FROM offers WHERE voice_id=?", (voice_id,)).fetchone():
            raise ValueError("Live offer identifier already consumed")
        if self._offers.execute("SELECT COUNT(*) FROM offers").fetchone()[0] >= 1024:
            raise ValueError("Live offer capacity exhausted")
        self._offers.execute("INSERT INTO offers VALUES (?,?)", (voice_id, key))
        self._offers.commit()  # Must happen before provider construction/POST.

    def _require_call(self, voice_id, owner, session):
        self._check_offer_storage()
        key = self._scope_key(owner, session)
        row = self._offers.execute("SELECT scope FROM offers WHERE voice_id=?", (voice_id,)).fetchone()
        if row is None or row[0] != key:
            raise ValueError("Live conversation unavailable")
        call = self.calls.get(voice_id)
        if call is not None and (call.owner != owner or call.session_id != session):
            raise ValueError("Live conversation unavailable")
        return call

    async def dispatch(self, context, payload, route):
        operation = payload.get("type")
        if operation not in OPERATIONS:
            raise ValueError("Unsupported live voice operation")
        fields = {k: v for k, v in payload.items() if k != "type"}
        allowed = {"agentId", "sessionId"}
        if operation == "voice.live.status":
            allowed |= {"provider"}
        else:
            allowed |= {"voiceId"}
        if operation == "voice.live.offer":
            allowed |= {"provider", "voice", "sdp"}
        if operation == "voice.live.control":
            allowed |= {"jobId", "runId", "expectedRevision", "requestId", "action", "text", "pendingId", "pendingRevision", "decision"}
        if set(fields) - allowed:
            raise ValueError("Invalid live voice fields")
        owner, session = await self._scope(fields, route)
        mode = fields.get("provider", "codex_subscription")
        if mode not in {"codex_subscription", "api_key"}:
            raise ValueError("Unsupported live voice provider")
        settings = self._settings()
        enabled = settings.get("enabled", True) is True
        configured = bool(self._api_key()) if mode == "api_key" else None
        if operation == "voice.live.status":
            return {"available": enabled and configured is not False, "enabled": enabled,
                    "signInRequired": self._auth_states.get(mode) == "requires_sign_in",
                    "provider": mode, "configured": configured,
                    "authState": self._auth_states.get(mode, "checked_on_start") if mode == "codex_subscription" else "configured" if configured else "requires_api_key",
                    "interruptSupported": False}
        self._storage()
        voice_id = _identifier(fields.get("voiceId"))
        if operation == "voice.live.offer":
            if not enabled or configured is False:
                raise ValueError("Live voice is not configured")
            if sum(not call.closed for call in self.calls.values()) >= 4:
                raise ValueError("Live voice capacity exhausted")
            if any(not call.closed and call.owner == owner for call in self.calls.values()):
                raise ValueError("A live conversation is already active")
            from .live_voice_provider import make_live_provider, validate_audio_sdp
            validate_audio_sdp(fields.get("sdp"))
            self._claim(voice_id, owner, session)
            call = _Call(voice_id, owner, session, route, mode)
            self.calls[voice_id] = call
            factory = self.provider_factory or make_live_provider
            try:
                kwargs = {"mode": mode, "on_event": lambda event: self._provider_event(call, event)}
                if mode == "api_key":
                    kwargs["api_key"] = self._api_key
                call.provider = factory(**kwargs)
                call.setup = asyncio.create_task(call.provider.create(fields["sdp"], voice=fields.get("voice", "cove" if mode == "codex_subscription" else "marin")))
                answer = await asyncio.shield(call.setup)
                if not isinstance(answer, str) or len(answer.encode("utf-8")) > 200000:
                    raise ValueError("Live answer exceeds workspace bounds")
                route.check_current()
                if call.closed or not self._current(owner):
                    raise ValueError("Live conversation ended during setup")
                self._auth_states[mode] = "authenticated"
                return {"voiceId": voice_id, "sdp": answer}
            except BaseException as error:
                await self._close(call)
                from .live_voice_auth import LiveAuthError
                if isinstance(error, LiveAuthError) or getattr(error, "code", None) == "authentication_failed":
                    from .workspace_control import WorkspaceControlError
                    self._auth_states[mode] = "requires_sign_in" if mode == "codex_subscription" else "requires_api_key"
                    raise WorkspaceControlError("Sign in to the selected voice provider on this host.",
                                                code="live_voice_requires_sign_in") from None
                raise
        if operation == "voice.live.close" and not self._offers.execute(
                "SELECT 1 FROM offers WHERE voice_id=?", (voice_id,)).fetchone():
            # A close can win before an offer finishes its async authorization.
            # Retain a consumed identity so that late offer cannot allocate.
            self._claim(voice_id, owner, session)
            return {"voiceId": voice_id, "closed": True, "cleanupConfirmed": False}
        call = self._require_call(voice_id, owner, session)
        if operation == "voice.live.close":
            if call is None:
                return {"voiceId": voice_id, "closed": True, "cleanupConfirmed": False}
            return await self._close(call)
        if operation == "voice.live.jobs":
            rows = self.jobs.list(owner, voice_id=voice_id, limit=200)
            return {"voiceId": voice_id, "jobs": [project_job(row) for row in rows]}
        if fields.get("action") == "interrupt":
            raise ValueError("Speech interrupt is unsupported; use native barge-in")
        job = self.jobs.get(owner, _identifier(fields.get("jobId")))
        if job.voice_id != voice_id:
            raise ValueError("Live job does not belong to this conversation")
        return await self._admit_control(job, fields, route)

    async def _event(self, call, event):
        if not self._current(call.owner):
            return
        try:
            async with asyncio.timeout(8):
                await call.route.send({"version": 1, "type": "voice.live.event", "voiceId": call.voice_id,
                                       "agentId": call.owner.agent_id, "sessionId": call.session_id,
                                       "event": event, "sentAt": int(time.time())})
        except Exception:
            # Reliable route failure is not permission to choose a new socket.
            self._spawn(self._close(call))

    def _spawn(self, coroutine):
        if self._closed or len(self._tasks) >= 128:
            coroutine.close()
            return None
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        def done(completed):
            self._tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()
        task.add_done_callback(done)
        return task

    async def _provider_event(self, call, event):
        if call.closed or not self._current(call.owner) or not isinstance(event, dict):
            return
        kind = event.get("kind")
        if kind in {"started", "sideband_attached"}:
            call.ready = True
            await self._flush_results(call)
        if kind in {"delegation", "delegation_context_required"}:
            call.route.check_current()
            text = event.get("text")
            if kind == "delegation_context_required":
                delegation_id = event.get("id")
                offset = event.get("offset_ms")
                text = call.delegation_briefs.get(delegation_id)
                if text is None and type(offset) is int and not call.context_incomplete:
                    texts = [row[1] for row in call.transcripts if row[0] is not None and call.context_offset < row[0] <= offset]
                    text = "".join(texts)
                    if text and len(call.delegation_briefs) < 1024:
                        call.delegation_briefs[delegation_id] = text
                        call.context_offset = offset
            if not isinstance(text, str) or not text.strip():
                await self._event(call, {"kind": "provider_error", "code": "delegation_context_unavailable"})
                return
            job = await self.jobs.delegate(call.owner, voice_id=call.voice_id,
                                           delegation_id=event.get("id"), text=text)
            await self._event(call, {"kind": "job", "job": project_job(job)})
            return
        if kind in {"transcript_delta", "transcript_done"}:
            if event.get("role") == "user" and isinstance(event.get("text"), str):
                end = event.get("end_ms")
                call.transcripts.append((end, event["text"]))
                while len(call.transcripts) > 128 or sum(len(row[1].encode("utf-8")) for row in call.transcripts) > 16384:
                    dropped = call.transcripts.pop(0)
                    if call.mode == "api_key" and dropped[0] is not None and dropped[0] > call.context_offset:
                        call.context_incomplete = True
        if kind in {"started", "sideband_attached", "transcript_delta", "transcript_done", "audio_cleared", "provider_error", "transport_closed", "session_closed"}:
            await self._event(call, event)
        if kind in {"transport_closed", "session_closed", "provider_error"}:
            self._spawn(self._close(call))

    async def _submit(self, job):
        call = self.calls.get(job.voice_id)
        if call is None or not self._current(job.owner):
            raise ValueError("Live delegation owner unavailable")
        binding = _JobBinding(job, call.route)
        self.bindings[job.job_id] = binding
        try:
            await self._turn(binding, job.message_id, job.text, call.route)
            if binding.job.revision == job.revision:
                binding.job = self._ledger.running(job.owner, job.job_id, run_id=job.run_id, expected_revision=job.revision)
            self._publish_job(binding)
        except BaseException:
            self._uncertain(binding)
            raise

    async def _turn(self, binding, message_id, text, route, behavior=None, *, track=True):
        job = binding.job
        if not self._current(job.owner):
            raise ValueError("Live job owner unavailable")
        if track:
            binding.turns.setdefault(message_id, None)
            binding.routes[message_id] = route.owner
        token = current_reply_route.set(route)
        try:
            message = UserMessage(message_id, job.session_id, job.owner.agent_id,
                                  job.owner.device_id, "Loopdy", "Loopdy", text, int(time.time()), behavior=behavior)
            sender_id = self.adapter.link_client.identity_registry.remember(
                sender_device_id=job.owner.device_id, actor_id=job.owner.device_id,
                actor_name="Loopdy", device_name="Loopdy")
            turn = InboundLinkTurn(message, sender_id, job.owner.device_id,
                                   sender_epoch=job.owner.device_epoch, target_host_id=job.owner.host_id,
                                   authority_origin=self._authority)
            async with asyncio.timeout(30):
                await self.adapter.receive_link_turn(turn)
        finally:
            current_reply_route.reset(token)
        lease = self.adapter._turn_replies.lookup(job.owner.agent_id, job.session_id, message_id)
        if behavior == "steer" and lease is None:
            # Ordinary /steer consumed inline: no new background turn exists.
            binding.turns.pop(message_id, None)
            binding.routes.pop(message_id, None)
            if binding.outcomes:
                self._finish_if_complete(binding, next(reversed(binding.outcomes)))
        elif not track and lease is not None:
            self.adapter._turn_replies.complete(lease)

    async def _admit_control(self, job, fields, route):
        action = fields.get("action")
        if action in {"steer", "queue"} and (not isinstance(fields.get("text"), str) or len(fields["text"].encode("utf-8")) > 3072):
            raise ValueError("Invalid job control text")
        if action == "approval" and type(fields.get("decision")) is not bool:
            raise ValueError("Invalid approval decision")
        if action == "clarification" and not isinstance(fields.get("decision"), str):
            raise ValueError("Invalid clarification decision")
        envelope = self._ledger.admit_control(job.owner, job.job_id, run_id=fields.get("runId"),
            expected_revision=fields.get("expectedRevision"), request_id=fields.get("requestId"), action=action,
            text=fields.get("text"), pending_id=fields.get("pendingId"), pending_revision=fields.get("pendingRevision"), decision=fields.get("decision"))
        key = (job.job_id, envelope.request_id)
        if envelope.is_new:
            binding = self.bindings.get(job.job_id)
            if binding is None or binding.job.run_id != envelope.job.run_id or binding.job.revision != envelope.expected_revision:
                self._ledger.finish_control(envelope, accepted=False)
            else:
                # Advance the exact callback binding synchronously with control
                # admission. Never bless an arbitrary callback with latest DB rev.
                binding.job = envelope.job
                if envelope.action in {"queue", "steer"}:
                    binding.turns[envelope.request_id] = None
                task = self._spawn(self._finish_control(envelope, route))
                if task is None:
                    self._ledger.finish_control(envelope, accepted=False)
                    self._uncertain(binding)
                else:
                    self._controls[key] = task
                    task.add_done_callback(lambda _: self._controls.pop(key, None))
        task = self._controls.get(key)
        if task is not None:
            await asyncio.shield(task)
        receipt = self._ledger.get_control(job.owner, job.job_id, envelope.request_id)
        return {"voiceId": job.voice_id, "status": receipt.state, "job": project_job(receipt.job)}

    async def _finish_control(self, envelope, route):
        accepted = False
        try:
            await self._control(envelope, route)
            accepted = True
        except Exception:
            pass  # The durable uncertain receipt, not exception text, is returned.
        finally:
            receipt = self._ledger.finish_control(envelope, accepted=accepted)
            binding = self.bindings.get(envelope.job.job_id)
            if binding is not None:
                if binding.job.run_id == envelope.job.run_id and binding.job.revision == envelope.job.revision:
                    binding.job = receipt.job
                if not accepted:
                    self._uncertain(binding)
                self._publish_job(binding)

    async def _control(self, envelope, route=None):
        binding = self.bindings[envelope.job.job_id]
        if (not self._current(binding.job.owner) or binding.job.run_id != envelope.job.run_id
                or binding.job.revision != envelope.job.revision or binding.job.terminal):
            raise ValueError("Job owner or dispatch revision changed")
        if envelope.action in {"approval", "clarification"}:
            resolver = binding.pending_resolver
            if resolver is None or resolver[0] != envelope.pending_id or resolver[1] != envelope.pending_revision:
                raise ValueError("Pending request changed")
            binding.pending_resolver = None
            result = resolver[2](envelope.decision)
            if inspect.isawaitable(result):
                result = await result
            if result is not True:
                raise ValueError("Pending request is no longer active")
            return
        route = route or binding.route
        if envelope.action == "cancel":
            token = self.adapter._control_response_task.set(asyncio.current_task())
            try:
                await self._turn(binding, envelope.request_id, "/stop", route, track=False)
            finally:
                self.adapter._control_response_task.reset(token)
        else:
            await self._turn(binding, envelope.request_id, envelope.text, route,
                             behavior=envelope.action, track=True)

    def observe(self, event_name, **coordinates):
        if self._closed:
            return
        lease = coordinates.get("lease")
        if lease is None:
            return
        binding = next((b for b in self.bindings.values() if b.job.session_id == lease.session_id and b.job.owner.agent_id == lease.profile), None)
        if (binding is None or lease.message_id not in binding.turns
                or binding.routes.get(lease.message_id) != lease.route.owner
                or binding.job.terminal or not self._current(binding.job.owner)):
            return
        if event_name == "processing_start":
            old = binding.turns[lease.message_id]
            if old is not None and old != lease.generation:
                return
            binding.turns[lease.message_id] = lease.generation
            event = coordinates.get("event")
            if event is not None:
                binding.session_keys.add(self.adapter._link_session_key(event.source))
            if binding.job.state == "dispatching":
                job = binding.job
                binding.job = self._ledger.running(job.owner, job.job_id, run_id=job.run_id, expected_revision=job.revision)
                self._publish_job(binding)
            return
        if binding.turns[lease.message_id] != lease.generation:
            return
        if event_name == "assistant_message" and coordinates.get("final") is True:
            binding.finals[lease.message_id] = _safe_text(coordinates.get("payload", {}).get("text"))
        elif event_name == "processing_complete":
            outcome = getattr(coordinates.get("outcome"), "value", coordinates.get("outcome"))
            binding.outcomes[lease.message_id] = outcome
            # Hermes may consume /queue inside one native agent chain rather
            # than starting another adapter task. Only its explicit terminal
            # inbound coordinate proves which queued controls were consumed.
            terminal = getattr(coordinates.get("event"), "ledger_message_id", None)
            if terminal in binding.turns:
                for message_id in binding.turns:
                    if binding.turns[message_id] is None:
                        binding.outcomes[message_id] = outcome
                        queued_lease = self.adapter._turn_replies.lookup(
                            binding.job.owner.agent_id, binding.job.session_id, message_id)
                        if queued_lease is not None:
                            self.adapter._turn_replies.complete(queued_lease)
                    if message_id == terminal:
                        break
            self._finish_if_complete(binding, lease.message_id)

    def _finish_if_complete(self, binding, message_id):
        if binding.job.terminal or not set(binding.turns) <= set(binding.outcomes):
            return
        states = set(binding.outcomes.values())
        state = "failed" if "failure" in states else "cancelled" if "cancelled" in states else "completed" if states == {"success"} else "uncertain"
        if state == "uncertain":
            self._uncertain(binding)
            return
        summary = binding.finals.get(message_id) if state == "completed" else None
        summary = summary or {"completed": "The delegated task completed. Open its chat for details.",
                              "failed": "The delegated task failed. Open its chat for details.",
                              "cancelled": "The delegated task was cancelled."}[state]
        job = binding.job
        try:
            binding.job = self._ledger.complete(job.owner, job.job_id, run_id=job.run_id,
                expected_revision=job.revision, state=state, summary=summary)
        except VoiceJobError:
            return
        binding.pending_resolver = None
        self._publish_job(binding, result=True)

    def _uncertain(self, binding):
        job = binding.job
        if not job.terminal and job.state != "uncertain":
            try:
                binding.job = self._ledger.uncertain(job.owner, job.job_id, run_id=job.run_id, expected_revision=job.revision)
            except VoiceJobError:
                pass
        self._publish_job(binding)

    def _publish_job(self, binding, *, result=False):
        job = binding.job
        call = self.calls.get(job.voice_id)
        if call is None or call.closed or not self._current(job.owner):
            return
        self._spawn(self._event(call, {"kind": "job", "job": project_job(job)}))
        if result:
            # Original delegation id + terminal revision are retained unchanged.
            call.results[job.delegation_id] = (job.run_id, job.revision, job.summary)
            self._spawn(self._flush_results(call))

    async def _flush_results(self, call):
        if not call.ready or call.closed or not self._current(call.owner):
            return
        for delegation_id, (run_id, revision, summary) in list(call.results.items()):
            key = (delegation_id, run_id, revision)
            if key in call.appended:
                continue
            call.appended.add(key)  # Before await: uncertain sends are never replayed.
            try:
                call.route.check_current()
                await call.provider.append_result(delegation_id, summary)
            except Exception:
                await self._close(call)
                return

    def agent_started(self, *, lease, stored_session_id):
        """Bind only an ID delivered by the stock pre-LLM lifecycle callback."""
        if self._loop is not None and lease is not None and isinstance(stored_session_id, str):
            self._loop.call_soon_threadsafe(self._bind_stored_session, lease, stored_session_id)

    def _bind_stored_session(self, lease, stored_session_id):
        if self._closed:
            return
        for binding in self.bindings.values():
            job = binding.job
            if (job.session_id != lease.session_id or job.owner.agent_id != lease.profile
                    or binding.turns.get(lease.message_id) != lease.generation
                    or binding.routes.get(lease.message_id) != lease.route.owner
                    or job.terminal or job.state == "uncertain" or not self._current(job.owner)):
                continue
            try:
                binding.job = self._ledger.bind_stored_session(job.owner, job.job_id,
                    run_id=job.run_id, expected_revision=job.revision, stored_session_id=stored_session_id)
                binding.session_keys.add(stored_session_id)
                if binding.job.revision != job.revision:
                    self._publish_job(binding)
            except VoiceJobError:
                self._uncertain(binding)
            return

    def approval_requested(self, **kwargs):
        """Called by Hermes' documented pre_approval_request observer hook."""
        if self._loop is None or self._closed:
            return
        session_key = kwargs.get("session_key")
        request_id, digest = kwargs.get("request_id"), kwargs.get("request_digest")
        if not isinstance(request_id, str) or not isinstance(digest, str):
            return
        # Hook can run in a tool thread; all mutable bindings stay on our loop.
        self._loop.call_soon_threadsafe(self._bind_approval, session_key, request_id, digest)

    def _bind_approval(self, session_key, request_id, digest):
        matches = [b for b in self.bindings.values() if session_key in b.session_keys and not b.job.terminal and self._current(b.job.owner)]
        if len(matches) == 1 and len(self._approvals) < 64:
            self._approvals[request_id] = (matches[0], digest)

    def present_approval(self, request):
        """Runs on the stock approval transport thread, not a gateway loop."""
        if self._loop is None or self._closed:
            return None
        future = asyncio.run_coroutine_threadsafe(self._approval(request), self._loop)
        try:
            return future.result(timeout=min(max(float(request.timeout_seconds), 0.1), 3600) + 1)
        except Exception:
            future.cancel()
            return request.respond("deny")

    async def _approval(self, request):
        bound = self._approvals.pop(request.request_id, None)
        if bound is None:
            return None
        binding, digest = bound
        if digest != request.digest or not self._current(binding.job.owner):
            return request.respond("deny")
        future = asyncio.get_running_loop().create_future()
        self._approval_futures.add(future)
        def resolve(decision):
            choice = "once" if decision else "deny"
            if future.done() or choice not in request.allowed_choices:
                return False
            future.set_result(choice)
            return True
        try:
            self._pending(binding, request.request_id, "approval",
                          _safe_text(request.description) or "Approval required. Review the task before allowing it.", resolve)
            async with asyncio.timeout(min(max(float(request.timeout_seconds), 0.1), 3600)):
                choice = await future
        except (TimeoutError, asyncio.CancelledError):
            choice = "deny"
        finally:
            self._approval_futures.discard(future)
            if binding.pending_resolver is not None and binding.pending_resolver[0] == request.request_id:
                binding.pending_resolver = None
        return request.respond(choice)

    def _pending(self, binding, pending_id, kind, prompt, resolver):
        job = binding.job
        binding.job = self._ledger.set_pending(job.owner, job.job_id, run_id=job.run_id,
            expected_revision=job.revision, pending_id=pending_id, kind=kind, prompt=prompt)
        binding.pending_resolver = (pending_id, binding.job.pending.revision, resolver)
        self._publish_job(binding)

    async def clarification(self, *, chat_id, question, clarify_id, session_key, lease):
        if lease is None:
            return False
        binding = next((b for b in self.bindings.values() if b.job.session_id == chat_id
                        and b.job.owner.agent_id == lease.profile and b.turns.get(lease.message_id) == lease.generation), None)
        if binding is None or not self._current(binding.job.owner):
            return False
        from tools.clarify_gateway import get_pending_for_session, resolve_gateway_clarify
        def resolve(decision):
            pending = get_pending_for_session(session_key, include_choice_prompts=True)
            if pending is None or str(getattr(pending, "clarify_id", "")) != clarify_id:
                return False
            return resolve_gateway_clarify(clarify_id, decision) is True
        pending = get_pending_for_session(session_key, include_choice_prompts=True)
        if pending is None or str(getattr(pending, "clarify_id", "")) != clarify_id:
            return False
        self._pending(binding, clarify_id, "clarification", _safe_text(question) or "A clarification is required. Open the task for details.", resolve)
        return True

    async def _close(self, call):
        call.closed = True
        call.ready = False
        call.results.clear()
        call.transcripts.clear()
        call.delegation_briefs.clear()
        if call.close_task is None:
            async def cleanup():
                result = {}
                if call.provider is not None:
                    try:
                        async with asyncio.timeout(12):
                            result = await call.provider.close()
                    except Exception:
                        pass
                return {"voiceId": call.voice_id, "closed": True,
                        "cleanupConfirmed": isinstance(result, dict) and result.get("cleanup_confirmed") is True}
            call.close_task = asyncio.create_task(cleanup())
        return await asyncio.shield(call.close_task)

    def transport_lost(self, *, transport, revoked=False):
        if revoked:
            for binding in tuple(self.bindings.values()):
                self._uncertain(binding)
            self._owners.clear()
        self._spawn(self.detach(transport=transport))

    async def detach(self, *, transport=None):
        calls = [call for call in self.calls.values() if not call.closed and (transport is None or call.route.owner.transport == transport)]
        await asyncio.gather(*(self._close(call) for call in calls), return_exceptions=True)

    async def _watch(self):
        try:
            while not self._closed:
                await asyncio.sleep(1)
                for call in list(self.calls.values()):
                    if call.closed:
                        continue
                    try:
                        if not self._current(call.owner):
                            raise ValueError("retired")
                        call.route.check_current()
                        if call.route.owner.transport == "direct" and time.monotonic() - call.last_probe >= 5:
                            call.last_probe = time.monotonic()
                            # A control-channel liveness probe, not a provider or
                            # audio readiness event. Original socket only.
                            self._spawn(self._event(call, {"kind": "control_ping"}))
                    except Exception:
                        await self._close(call)
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        if self._closed:
            return
        # Gateway shutdown is not voice detach and is never a job rerun trigger.
        await self.detach()
        for future in tuple(self._approval_futures):
            if not future.done():
                future.set_result("deny")
        self._approval_futures.clear()
        for binding in list(self.bindings.values()):
            self._uncertain(binding)
        self._closed = True
        if self._watch_task is not None:
            self._watch_task.cancel()
            await asyncio.gather(self._watch_task, return_exceptions=True)
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.jobs is not None:
            await self.jobs.aclose()
        if self._offers is not None:
            self._offers.close()
        if self._ledger is not None:
            self._ledger.close()
        self._approvals.clear()
        self._owners.clear()
        self.bindings.clear()
        self.calls.clear()
