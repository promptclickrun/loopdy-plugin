"""Finite stock-serve HTTP adapters for existing Loopdy domain services."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from .native_context import NativeAPIError, NativeContext, PROFILE_ID, native_context
from .store import CardTemplateConflict, CardTemplateLimit
from .workspace_control import card_template_projection


logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 196_608
MAX_TEMPLATES = 500
_REQUEST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def _error_response(error: NativeAPIError) -> JSONResponse:
    logger.warning("Loopdy native request rejected: %s", error.code)
    return JSONResponse(status_code=error.status, content={"error": {
        "code": error.code, "message": error.message,
        "retryable": error.status == 503, "details": {},
    }}, headers={"Cache-Control": "no-store"})


class _NativeRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def guarded(request: Request) -> Response:
            try:
                return await handler(request)
            except NativeAPIError as error:
                response = _error_response(error)
                request_id = request.headers.get("x-loopdy-request-id", "")
                if len(request.headers.getlist("x-loopdy-request-id")) == 1 and _REQUEST_ID.fullmatch(request_id):
                    response.headers["X-Loopdy-Request-ID"] = request_id
                return response
            except ClientDisconnect:
                return _error_response(NativeAPIError(400, "request_disconnected",
                                                     "The request was disconnected."))
            except Exception:
                # Auth providers and storage may include secrets/paths in exceptions.
                logger.error("Loopdy native request failed: native_service_unavailable")
                return _error_response(NativeAPIError(503, "native_service_unavailable",
                                                     "The native plugin service is unavailable."))
        return guarded


router = APIRouter(prefix="/native", route_class=_NativeRoute)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")


class _TemplateSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    version: StrictInt = Field(gt=0, le=9_007_199_254_740_991)
    name: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=1_000)
    author: str = Field(min_length=1, max_length=120)
    license: str = Field(min_length=1, max_length=120)
    minimum_card_version: StrictInt = Field(ge=1, le=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _TemplateBundle(_TemplateSummary):
    parameters_schema: dict[str, Any]
    document: dict[str, Any]


class _Install(_Body):
    template: _TemplateBundle


class _Remove(_Body):
    templateId: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    version: StrictInt = Field(gt=0, le=9_007_199_254_740_991)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_number(_value):
    raise ValueError("Non-finite JSON number")


async def _body(request: Request, model: type[_Body]) -> _Body:
    if request.query_params:
        raise NativeAPIError(422, "invalid_request", "Query fields are not supported.")
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise NativeAPIError(422, "invalid_request", "A JSON request is required.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_BODY_BYTES:
            raise NativeAPIError(413, "payload_too_large", "The request exceeds the byte limit.")
        content.extend(chunk)
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_invalid_number)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 24:
                raise ValueError("JSON nesting limit")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        body = model.model_validate(value)
        if PROFILE_ID.fullmatch(body.agentId) is None:
            raise ValueError("Invalid profile")
        return body
    except (ValueError, UnicodeError, RecursionError, ValidationError):
        raise NativeAPIError(422, "invalid_request", "The native request is invalid.") from None


def _headers(context: NativeContext, request_id: str | None = None) -> dict[str, str]:
    result = {"Cache-Control": "no-store", "ETag": context.etag}
    if request_id is not None:
        result["X-Loopdy-Request-ID"] = request_id
    return result


def _response(value: dict, context: NativeContext, request_id: str | None = None) -> Response:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True, allow_nan=False).encode("utf-8")
    maximum = 16_384 if request_id is None else MAX_BODY_BYTES
    if len(encoded) > maximum:
        raise NativeAPIError(413, "payload_too_large", "The response exceeds the byte limit.")
    return Response(encoded, media_type="application/json", headers=_headers(context, request_id))


def _precondition(request: Request, context: NativeContext) -> str:
    if request.headers.get("if-match") is None:
        raise NativeAPIError(428, "context_required", "Load native context before this request.")
    if len(request.headers.getlist("if-match")) != 1 or request.headers["if-match"] != context.etag:
        raise NativeAPIError(412, "context_changed", "The native context changed; refresh before retrying.")
    request_id = request.headers.get("x-loopdy-request-id", "")
    if len(request.headers.getlist("x-loopdy-request-id")) != 1 or _REQUEST_ID.fullmatch(request_id) is None:
        raise NativeAPIError(422, "invalid_request", "A canonical request ID is required.")
    return request_id


@router.get("/context")
async def context(request: Request) -> Response:
    owner = native_context(request)
    if request.query_params:
        raise NativeAPIError(422, "invalid_request", "Native context takes no query or body.")
    async for chunk in request.stream():
        if chunk:
            raise NativeAPIError(422, "invalid_request", "Native context takes no query or body.")
    return _response(owner.payload(), owner)


def _summary(template: dict) -> dict:
    return _TemplateSummary.model_validate(card_template_projection(template)).model_dump()


def _templates(request: Request, owner: NativeContext, body: _Body, operation: str) -> dict:
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; refresh before retrying.")
    from hermes_cli.profiles import profile_exists
    from hermes_constants import (
        get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
    )
    from .adapter import get_service

    token = set_hermes_home_override(get_process_hermes_home())
    try:
        if not profile_exists(body.agentId):
            raise NativeAPIError(404, "profile_not_found", "The selected profile no longer exists.")
        store = get_service().store
        try:
            if operation == "list":
                templates = store.list_card_templates(profile=body.agentId, limit=MAX_TEMPLATES)
                result = {"templates": [_summary(item) for item in templates]}
            elif operation == "install" and isinstance(body, _Install):
                installed = store.install_card_template(profile=body.agentId, template=body.template.model_dump())
                result = {"changed": installed["changed"],
                          "template": _summary(installed["template"])}
            elif operation == "remove" and isinstance(body, _Remove):
                result = store.remove_card_template(profile=body.agentId, template_id=body.templateId,
                                                    version=body.version, sha256=body.sha256)
            else:
                raise NativeAPIError(422, "invalid_request", "The template request is invalid.")
        except CardTemplateConflict:
            raise NativeAPIError(409, "template_conflict", "The template version or content changed.") from None
        except CardTemplateLimit:
            raise NativeAPIError(413, "catalog_too_large", "The template catalog exceeds the row limit.") from None
        except ValueError:
            raise NativeAPIError(422, "invalid_template", "The template data is invalid.") from None
        if native_context(request) != owner:
            raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
        return {"agentId": body.agentId, **result}
    finally:
        reset_hermes_home_override(token)


async def _template_request(request: Request, model: type[_Body], operation: str) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    if "native-card-templates-v1" not in owner.features:
        raise NativeAPIError(503, "templates_unavailable", "Native card templates are unavailable.")
    body = await _body(request, model)
    result = await run_in_threadpool(_templates, request, owner, body, operation)
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
    return _response(result, owner, request_id)


@router.post("/cards/templates/list")
async def list_templates(request: Request) -> Response:
    return await _template_request(request, _Body, "list")


@router.post("/cards/templates/install")
async def install_template(request: Request) -> Response:
    return await _template_request(request, _Install, "install")


@router.post("/cards/templates/remove")
async def remove_template(request: Request) -> Response:
    return await _template_request(request, _Remove, "remove")
