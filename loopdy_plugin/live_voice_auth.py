"""Host-only Live credentials. No stores, refreshers, subprocesses or API fallback.

Resolution is lazy and occurs only after the caller has authorized voice setup.
JWT decoding derives the account header; it is NOT authentication of a Link user.
"""
from __future__ import annotations

import asyncio
import base64
import inspect
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_MODEL = "gpt-live-1-codex"
_ACCOUNT = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")


class LiveAuthError(RuntimeError):
    """Fixed safe message: never wrap resolver text or serialize its result."""

    def __init__(self) -> None:
        super().__init__("Live voice authentication unavailable for the selected provider.")


@dataclass(frozen=True, repr=False)
class LiveCredentials:
    """Scoped host memory only; never return this through the adapter protocol."""

    bearer: str = field(repr=False)
    account_id: str | None = field(default=None, repr=False)
    credential_id: str | None = field(default=None, repr=False)
    identity_headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __repr__(self) -> str:
        return "<LiveCredentials redacted>"


def _token(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 32768
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise LiveAuthError()
    return value


def _account(token: str) -> str:
    try:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise ValueError()
        payload = parts[1]
        claims = json.loads(base64.b64decode(
            payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True))
        account = claims["https://api.openai.com/auth"]["chatgpt_account_id"]
        if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
            raise ValueError()
        return account
    except Exception:
        raise LiveAuthError() from None


def _official_base(value: Any) -> bool:
    # The shared resolver may finalize a Responses URL. Neither route is used
    # as a network destination here; the voice transport has fixed constants.
    return isinstance(value, str) and value in {
        CODEX_BASE_URL, CODEX_BASE_URL + "/",
        CODEX_BASE_URL + "/responses", CODEX_BASE_URL + "/responses/",
    }


def validate_codex_runtime(runtime: Any, *, expected_account_id: str | None = None) -> LiveCredentials:
    """Validate the exact selected pool entry without moving the pool cursor."""
    try:
        if not isinstance(runtime, Mapping):
            raise LiveAuthError()
        if (runtime.get("provider") != "openai-codex"
                or runtime.get("api_mode") != "codex_responses"
                or not _official_base(runtime.get("base_url"))
                or runtime.get("auth_mode") not in (None, "chatgpt")
                or runtime.get("auth_type") not in (None, "oauth")):
            raise LiveAuthError()
        token = _token(runtime.get("api_key"))
        account = _account(token)
        if expected_account_id is not None and account != expected_account_id:
            raise LiveAuthError()
        for name in ("account_id", "chatgpt_account_id"):
            if runtime.get(name) is not None and runtime[name] != account:
                raise LiveAuthError()
        source = runtime.get("source")
        if not isinstance(source, str) or not source or "api_key" in source.lower():
            raise LiveAuthError()
        pool = runtime.get("credential_pool")
        credential_id = None
        if pool is not None:
            # Runtime currently doesn't return an entry ID. Find exactly one
            # matching bearer using public entries(), not mutable current().
            matches = [entry for entry in pool.entries()
                       if entry.runtime_api_key == token]
            if len(matches) != 1:
                raise LiveAuthError()
            entry = matches[0]
            if (entry.provider != "openai-codex" or entry.auth_type != "oauth"
                    or entry.source != source or not isinstance(entry.id, str)
                    or not entry.id or len(entry.id) > 256
                    or (entry.base_url and not _official_base(entry.base_url))):
                raise LiveAuthError()
            credential_id = entry.id
            if runtime.get("credential_id") not in (None, credential_id):
                raise LiveAuthError()
        elif source != "hermes-auth-store" or runtime.get("credential_id") is not None:
            # Fail closed for unknown/custom singleton provenance. Pool sources
            # are checked by their OAuth entry rather than a growing allowlist.
            raise LiveAuthError()
        return LiveCredentials(token, account, credential_id)
    except Exception:
        raise LiveAuthError() from None


def _default_runtime_resolver(**kwargs: Any) -> Mapping[str, Any]:
    from hermes_cli.runtime_provider import resolve_runtime_provider
    return resolve_runtime_provider(**kwargs)


class CodexLiveAuth:
    """Inject a sync/async runtime resolver for local credential-free fixtures.

    No explicit refresh/retry is performed here. Hermes owns its normal managed
    resolution/refresh; one call is pinned to one account and one selected entry.
    A cancelled sync resolver can finish in its thread, but cannot initiate a
    Live POST or have its result adopted by another voice generation.
    """

    def __init__(self, resolver: Callable[..., Any] | None = None, *,
                 expected_account_id: str | None = None) -> None:
        self._resolver = resolver or _default_runtime_resolver
        self._expected_account_id = expected_account_id
        self._default = resolver is None

    async def resolve(self) -> LiveCredentials:
        try:
            kwargs = {"requested": "openai-codex", "target_model": CODEX_MODEL}
            if inspect.iscoroutinefunction(self._resolver):
                runtime = await self._resolver(**kwargs)
            else:
                runtime = await asyncio.to_thread(self._resolver, **kwargs)
                if inspect.isawaitable(runtime):
                    runtime = await runtime
            credentials = validate_codex_runtime(
                runtime, expected_account_id=self._expected_account_id)
            if not self._default:
                return credentials
            # Leaf official helper supplies genuine installed Hermes identity.
            # Copy only these known fields, never arbitrary resolver headers.
            from agent.codex_headers import codex_cloudflare_headers
            headers = codex_cloudflare_headers(credentials.bearer, base_url=CODEX_BASE_URL)
            if headers.get("ChatGPT-Account-ID") != credentials.account_id:
                raise LiveAuthError()
            identity = tuple((key, headers[key]) for key in ("User-Agent", "originator"))
            return LiveCredentials(credentials.bearer, credentials.account_id,
                                   credentials.credential_id, identity)
        except Exception:
            raise LiveAuthError() from None


class PublicLiveAuth:
    """Explicit API billing only. No environment lookup or subscription fallback."""

    def __init__(self, api_key: str | Callable[[], Any], *, mode: str) -> None:
        if mode != "api_key":
            raise LiveAuthError()
        self._key = api_key

    def __repr__(self) -> str:
        return "<PublicLiveAuth redacted>"

    async def resolve(self) -> LiveCredentials:
        try:
            value = self._key
            if callable(value):
                if inspect.iscoroutinefunction(value):
                    value = await value()
                else:
                    value = await asyncio.to_thread(value)
                    if inspect.isawaitable(value):
                        value = await value
            return LiveCredentials(_token(value))
        except Exception:
            raise LiveAuthError() from None
