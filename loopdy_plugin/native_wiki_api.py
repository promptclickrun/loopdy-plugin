"""Native Wiki uses the verified Hermes principal, never a fabricated device."""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, RootModel
from starlette.concurrency import run_in_threadpool

from .native_api import _NativeRoute, _body, _precondition, _response
from .native_context import NativeAPIError, NativeContext, native_context
from .wiki_contract import bounded_result, validate_payload
from .wiki_service import WikiService, WikiServiceError
from .wiki_transport import execute_wiki_operation


router = APIRouter(prefix="/native/wiki", route_class=_NativeRoute)
logger = logging.getLogger(__name__)
CAPABILITY = "native-wiki-v1"
_PATHS = (
    ("roots", "wiki.roots"), ("connect", "wiki.connect"), ("resolve", "wiki.resolve"),
    ("list", "wiki.list"), ("read", "wiki.read"), ("search", "wiki.search"),
    ("image", "wiki.image"), ("save/begin", "wiki.save.begin"),
    ("save/chunk", "wiki.save.chunk"), ("save/commit", "wiki.save.commit"),
    ("save/status", "wiki.save.status"),
    ("disconnect", "wiki.disconnect"),
)


class _Payload(RootModel[dict[str, Any]]):
    pass


class _Disconnect(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    wikiId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")


def _identity_digest(values: list[str]) -> str:
    return hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _execute(request: Request, owner: NativeContext, operation: str, payload: dict) -> dict:
    from hermes_constants import (
        get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
    )
    from hermes_cli.profiles import profile_exists

    def check():
        if native_context(request) != owner:
            raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the Wiki operation.")

    check()
    home = get_process_hermes_home()
    token = set_hermes_home_override(home)
    try:
        if not profile_exists(payload["agentId"]):
            raise NativeAPIError(404, "profile_not_found", "The selected profile no longer exists.")
        principal = _identity_digest(["loopdy-native-principal-v1", owner.provider, owner.user_id])
        authority = _identity_digest(["loopdy-native-wiki-v1", str(home.resolve()), principal])
        service = WikiService(home / "plugin-data" / "loopdy" / "wiki", authority_id=authority,
                              principal_id=principal, owner_check=check, protected_roots=(home,))
        result = (service.disconnect(payload["wikiId"], profile_id=payload["agentId"])
                  if operation == "wiki.disconnect"
                  else execute_wiki_operation(service, operation, payload, device_id=None))
        check()
        try:
            return bounded_result(result)
        except (ValueError, UnicodeError):
            raise NativeAPIError(413, "payload_too_large", "The Wiki response exceeds the transfer limit.") from None
    finally:
        reset_hermes_home_override(token)


def _wiki_error(error: WikiServiceError, request_id: str) -> JSONResponse:
    codes = {
        "INVALID_REQUEST": 422, "INVALID_PATH": 400, "REVISION_REQUIRED": 400,
        "WIKI_NOT_ALLOWED": 404, "WIKI_AUTHORITY_CONFLICT": 409, "WIKI_AMBIGUOUS": 409,
        "PATH_NOT_FOUND": 404, "PATH_PROTECTED": 404, "OPERATION_NOT_FOUND": 404,
        "OPERATION_CONFLICT": 409, "REVISION_STALE": 409, "WIKI_OWNER_CHANGED": 409,
        "READ_ONLY": 403, "UNSUPPORTED_CONTENT": 422, "UPLOAD_INCOMPLETE": 409,
        "DIGEST_MISMATCH": 422, "SECRET_SCAN_BLOCKED": 422, "HARD_LINK_UNSAFE": 422,
        "CAPABILITY_UNSUPPORTED": 501, "QUOTA_EXCEEDED": 413, "DIRECTORY_OVERSIZED": 413,
        "STATE_BUSY": 503, "STATE_UNAVAILABLE": 503,
    }
    logger.warning("Loopdy native Wiki rejected: %s", error.code)
    return JSONResponse(error.envelope(), status_code=codes.get(error.code, 503),
                        headers={"Cache-Control": "no-store", "X-Loopdy-Request-ID": request_id})


def _handler(operation: str):
    async def handle(request: Request) -> Response:
        owner = native_context(request)
        request_id = _precondition(request, owner)
        if CAPABILITY not in owner.features:
            raise NativeAPIError(501, "wiki_unavailable", "Secure native Wiki access is unavailable.")
        if operation == "wiki.disconnect":
            body = await _body(request, _Disconnect)
            payload = body.model_dump()
        else:
            body = await _body(request, _Payload)
            try:
                payload = validate_payload(operation, body.root)
            except ValueError:
                raise NativeAPIError(422, "invalid_request", "The Wiki request is invalid.") from None
        try:
            result = await run_in_threadpool(_execute, request, owner, operation, payload)
        except WikiServiceError as error:
            return _wiki_error(error, request_id)
        if native_context(request) != owner:
            raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the Wiki operation.")
        return _response(result, owner, request_id)
    return handle


for _path, _operation in _PATHS:
    router.add_api_route("/" + _path, _handler(_operation), methods=["POST"],
                         name="native_" + _operation.replace(".", "_"))
