"""Authenticated Hermes dashboard API consumed by the Loopdy app."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from loopdy_plugin.adapter import data_path, get_service  # noqa: E402
from loopdy_plugin.attachments import AttachmentStore, MAX_ITEMS  # noqa: E402
from loopdy_plugin.events import EVENT_TYPES  # noqa: E402

from loopdy_plugin.generative_ui import (  # noqa: E402
    GenerativeUIError,
    validate_submission_values,
)
from loopdy_plugin.link_contracts import PLUGIN_VERSION  # noqa: E402
from loopdy_plugin.provider import DeliveryError  # noqa: E402
from loopdy_plugin.targets import validate_target  # noqa: E402
from loopdy_plugin.workspace_control import HermesWorkspaceBackend  # noqa: E402
from loopdy_plugin.workspace_git import (  # noqa: E402
    WorkspaceGitError,
    WorkspaceGitService,
)
from loopdy_plugin.workspace_files_api import router as workspace_files_router  # noqa: E402
from loopdy_plugin.native_api import router as native_router  # noqa: E402
from loopdy_plugin.room_activity_api import router as room_activity_router  # noqa: E402
from loopdy_plugin.native_wiki_api import router as native_wiki_router  # noqa: E402
from loopdy_plugin.native_project_git import router as native_project_git_router  # noqa: E402
from loopdy_plugin.native_threads import router as native_threads_router  # noqa: E402
from loopdy_plugin.agent_templates import (  # noqa: E402
    capability as agent_templates_capability,
    router as agent_templates_router,
)


router = APIRouter()
router.include_router(workspace_files_router)
router.include_router(native_router)
router.include_router(room_activity_router, prefix="/native")
router.include_router(native_wiki_router)
router.include_router(native_project_git_router)
router.include_router(native_threads_router)
router.include_router(agent_templates_router)
from loopdy_plugin.managed_notifications_api import router as managed_notifications_router
router.include_router(managed_notifications_router)
_WORKSPACE_GIT_STATE_PATH = data_path().with_name("workspace-git.sqlite3")
_service = None
_workspace_git_service = None
_attachment_store = None
_TIME = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_ZONE = re.compile(r"^[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$")
_EXPO_TOKEN = re.compile(r"^(?:Exponent|Expo)PushToken\[[A-Za-z0-9._~-]{8,200}\]$")
_APNS_TOKEN = re.compile(r"^[0-9a-fA-F]{64,200}$")
_DETAIL_MODES = ("automatic", "minimal", "detailed")
_clock = lambda: int(time.time())


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProviderUpdate(StrictBody):
    mode: Literal["managed", "direct"]


class DeviceRegistration(StrictBody):
    device_id: str = Field(min_length=1, max_length=180)
    provider: Literal["managed", "direct"]
    push_token: str = Field(min_length=1, max_length=512)
    token_environment: Literal["production", "sandbox"] = "production"
    label: str = Field(default="", max_length=120)
    groups: list[str] = Field(default_factory=list, max_length=50)


class LiveActivityRegistration(StrictBody):
    session_id: str = Field(min_length=1, max_length=180)
    live_session_id: str = Field(min_length=1, max_length=180)
    profile: str = Field(default="default", min_length=1, max_length=80)
    activity_id: str = Field(min_length=1, max_length=180)
    push_token: str = Field(min_length=64, max_length=512)
    environment: Literal["production", "sandbox"] = "production"


class QuietHours(StrictBody):
    start: str = Field(min_length=5, max_length=5)
    end: str = Field(min_length=5, max_length=5)


class PreferenceUpdate(StrictBody):
    detail_mode: Literal["automatic", "minimal", "detailed"] = "automatic"
    lock_screen_previews: bool = True
    enabled_types: list[str] = Field(
        default_factory=lambda: sorted(EVENT_TYPES),
        max_length=len(EVENT_TYPES),
    )
    notifications_enabled: bool = True
    priority_sound: bool = True
    quiet_hours: QuietHours | None = None
    timezone: str | None = Field(default=None, max_length=100)
    preferences_version: Literal[2] = 2


class TestRequest(StrictBody):
    target: str = Field(default="all", min_length=1, max_length=140)


class ApprovalResponse(StrictBody):
    choice: Literal["once", "session", "always", "deny"]
    request_digest: str = Field(min_length=1, max_length=180)


class EventDismissRequest(StrictBody):
    event_ids: list[str] = Field(default_factory=list, max_length=200)
    event_types: list[str] = Field(default_factory=list, max_length=len(EVENT_TYPES))
    created_before: StrictInt | None = Field(default=None, ge=0, le=9_999_999_999)

    @field_validator("event_ids")
    @classmethod
    def validate_event_ids(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 220 for value in values):
            raise ValueError("event_ids contains an invalid identifier")
        if len(values) != len(set(values)):
            raise ValueError("event_ids must be unique")
        return values

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, values: list[str]) -> list[str]:
        if any(value not in EVENT_TYPES for value in values):
            raise ValueError("event_types contains an unsupported event type")
        if len(values) != len(set(values)):
            raise ValueError("event_types must be unique")
        return values

    @model_validator(mode="after")
    def validate_selector(self):
        if bool(self.event_ids) == bool(self.event_types):
            raise ValueError("Choose event_ids or event_types")
        if self.event_types and self.created_before is None:
            raise ValueError("created_before is required when dismissing by type")
        return self


class EventStateRequest(StrictBody):
    is_read: StrictBool
    is_pinned: StrictBool


class AttachmentItem(StrictBody):
    id: str = Field(min_length=1, max_length=180)
    text: str


class AttachmentResolveRequest(StrictBody):
    profile: str = Field(default="default", min_length=1, max_length=80)
    session_id: str = Field(min_length=1, max_length=180)
    items: list[AttachmentItem] = Field(max_length=MAX_ITEMS)


class FormOwner(StrictBody):
    profile: str = Field(min_length=1, max_length=80)
    session_id: str = Field(min_length=1, max_length=180)


class FormActionRequest(StrictBody):
    schema_: Literal["loopdy.generative_ui.action_request"] = Field(alias="schema")
    version: Literal[2]
    kind: Literal["submit_form"]
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    owner: FormOwner
    submitted_at: datetime
    values: dict[str, Any]


class WorkspaceBody(StrictBody):
    workspace_id: str = Field(min_length=1, max_length=80)


class WorkspaceStageInput(StrictBody):
    mode: Literal["stage", "unstage"]
    paths: list[str] = Field(min_length=1, max_length=500)


class WorkspaceCommitInput(StrictBody):
    message: str = Field(min_length=1, max_length=10_000)


class WorkspacePushInput(StrictBody):
    remote: str = Field(min_length=1, max_length=180)
    branch: str = Field(min_length=1, max_length=180)


class WorkspaceFetchInput(StrictBody):
    remote: str = Field(min_length=1, max_length=180)


class WorkspacePullInput(WorkspacePushInput):
    strategy: Literal["ff-only"]


WorkspaceOperationInput = (
    WorkspaceStageInput
    | WorkspaceCommitInput
    | WorkspacePushInput
    | WorkspaceFetchInput
    | WorkspacePullInput
)


class WorkspacePrepare(WorkspaceBody):
    operation: Literal["stage", "commit", "push", "fetch", "pull"]
    input: WorkspaceOperationInput
    expected_status_token: str = Field(min_length=8, max_length=100)


class WorkspaceExecution(WorkspaceBody):
    expected_status_token: str = Field(min_length=8, max_length=100)
    confirmation_token: str = Field(min_length=8, max_length=200)
    idempotency_key: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )


class WorkspaceStageExecution(WorkspaceExecution, WorkspaceStageInput):
    pass


class WorkspaceCommitExecution(WorkspaceExecution, WorkspaceCommitInput):
    pass


class WorkspacePushExecution(WorkspaceExecution, WorkspacePushInput):
    pass


class WorkspaceFetchExecution(WorkspaceExecution, WorkspaceFetchInput):
    pass


class WorkspacePullExecution(WorkspaceExecution, WorkspacePullInput):
    pass


@router.get("/capabilities")
def capabilities() -> dict[str, Any]:
    health = _active_service().health()
    return {
        "plugin": "loopdy",
        "plugin_version": PLUGIN_VERSION,
        "schema_version": 2,
        "channel": "loopdy",
        "default_provider": "managed",
        "provider": health,
        "providers": ["managed", "direct"],
        "detail_modes": list(_DETAIL_MODES),
        "approval_transport": "loopdy",
        "approval_choices": ["once", "session", "always", "deny"],
        "event_types": sorted(EVENT_TYPES),
        "preferences_schema_version": 2,
        "targets": ["all", "device:<id>", "group:<id>"],
        "direct_setup": {
            "host_only": True,
            "required": ["team_id", "key_id", "topic", "environment", "key_path"],
            "cli": "hermes loopdy configure-apns",
        },
        "capabilities": {
            "device_management": True,
            "notification_preferences": True,
            "event_inbox": True,
            "approval_responses": True,
            "lifecycle_notifications": True,
            "live_activities": True,
            "native_channel": True,
            "standalone_cron_delivery": True,
            "proactive_delivery": True,
            "provider_selection": True,
            "native_agent_attachments": True,
        },
        "agent_attachments": {
            "schema_version": 1,
            "resolve": "/attachments/resolve",
            "download": "/attachments/{attachment_id}",
        },
        "generative_ui": {
            "schema": "loopdy.generative_ui",
            "supported_versions": [1, 2],
            "preferred_version": 2,
            "components": {
                "1": ["summary", "metrics", "list", "timeline"],
                "2": [
                    "weather_forecast",
                    "sports_game",
                    "stock_quote",
                    "chart",
                    "dashboard",
                    "form",
                ],
            },
            "actions": {"2": ["submit_form"]},
            "max_payload_bytes": {"1": 16_384, "2": 32_768},
            "max_action_bytes": 8_192,
        },
        "workspace_git": _active_workspace_git().capabilities(),
        "agent_templates": agent_templates_capability(),
    }


@router.post("/attachments/resolve")
def resolve_attachments(body: AttachmentResolveRequest) -> dict[str, Any]:
    try:
        return {
            "schema_version": 1,
            "items": _active_attachment_store().resolve(
                profile=body.profile,
                session_id=body.session_id,
                items=[item.model_dump() for item in body.items],
            ),
        }
    except Exception as error:
        raise _api_error(error) from error


@router.get("/attachments/{attachment_id}")
def download_attachment(
    attachment_id: str,
    profile: str = Query(default="default", min_length=1, max_length=80),
) -> Response:
    attachment = _active_attachment_store().read(
        profile=profile,
        attachment_id=attachment_id,
    )
    if attachment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attachment not found",
        )
    filename = quote(attachment["name"], safe="")
    return Response(
        content=attachment["content"],
        media_type=attachment["mime_type"],
        headers={
            "Cache-Control": "private, max-age=3600",
            "Content-Disposition": f"inline; filename*=UTF-8''{filename}",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/workspace-git/capabilities")
def workspace_git_capabilities() -> dict[str, Any]:
    return _active_workspace_git().capabilities()


@router.post("/workspace-git/status", response_model=None)
def workspace_git_status(body: WorkspaceBody) -> dict[str, Any] | JSONResponse:
    try:
        return _active_workspace_git().status(body.workspace_id)
    except WorkspaceGitError as error:
        return _workspace_git_error_response(error)


@router.post("/workspace-git/prepare", response_model=None)
def workspace_git_prepare(body: WorkspacePrepare, request: Request) -> dict[str, Any] | JSONResponse:
    expected_type = {
        "stage": WorkspaceStageInput,
        "commit": WorkspaceCommitInput,
        "push": WorkspacePushInput,
        "fetch": WorkspaceFetchInput,
        "pull": WorkspacePullInput,
    }[body.operation]
    if type(body.input) is not expected_type:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Operation input does not match the selected operation",
        )
    try:
        return _active_workspace_git().prepare(
            workspace_id=body.workspace_id,
            operation=body.operation,
            input_=body.input.model_dump(),
            expected_status_token=body.expected_status_token,
            connection_id=_connection_binding(request),
        )
    except WorkspaceGitError as error:
        return _workspace_git_error_response(error)


@router.post("/workspace-git/stage", response_model=None)
def workspace_git_stage(body: WorkspaceStageExecution, request: Request) -> dict[str, Any] | JSONResponse:
    return _execute_workspace_git("stage", body, request)


@router.post("/workspace-git/commit", response_model=None)
def workspace_git_commit(body: WorkspaceCommitExecution, request: Request) -> dict[str, Any] | JSONResponse:
    return _execute_workspace_git("commit", body, request)


@router.post("/workspace-git/push", response_model=None)
def workspace_git_push(body: WorkspacePushExecution, request: Request) -> dict[str, Any] | JSONResponse:
    return _execute_workspace_git("push", body, request)


@router.post("/workspace-git/fetch", response_model=None)
def workspace_git_fetch(body: WorkspaceFetchExecution, request: Request) -> dict[str, Any] | JSONResponse:
    return _execute_workspace_git("fetch", body, request)


@router.post("/workspace-git/pull", response_model=None)
def workspace_git_pull(body: WorkspacePullExecution, request: Request) -> dict[str, Any] | JSONResponse:
    return _execute_workspace_git("pull", body, request)


@router.get("/provider")
def get_provider() -> dict[str, Any]:
    service = _active_service()
    receipts = service.reconcile_receipts()
    return {**service.health(), "receipts": receipts}


@router.put("/provider")
def set_provider(body: ProviderUpdate) -> dict[str, Any]:
    try:
        return _active_service().set_provider_mode(body.mode)
    except Exception as error:
        raise _api_error(error) from error


@router.get("/devices")
def list_devices() -> dict[str, Any]:
    return {"devices": [_public_device(value) for value in _active_service().store.list_devices()]}


@router.post("/devices", status_code=status.HTTP_201_CREATED)
def register_device(body: DeviceRegistration) -> dict[str, Any]:
    try:
        verdict = validate_target(f"device:{body.device_id}")
        if verdict is not True:
            raise ValueError(f"Invalid device ID: {verdict}")
        _validate_push_token(body.provider, body.push_token)
        result = _active_service().register_device(
            device_id=body.device_id,
            endpoint_id=body.push_token,
            provider=body.provider,
            token_environment=body.token_environment,
            label=body.label,
            groups=_groups(body.groups),
        )
        return {**result, "token_fingerprint": _token_fingerprint(body.push_token)}
    except Exception as error:
        raise _api_error(error) from error


@router.delete("/devices/{device_id}")
def revoke_device(device_id: str) -> dict[str, Any]:
    try:
        return _active_service().revoke_device(device_id)
    except Exception as error:
        raise _api_error(error) from error


@router.post("/live-activities", status_code=status.HTTP_201_CREATED)
def register_live_activity(body: LiveActivityRegistration) -> dict[str, Any]:
    try:
        _validate_push_token("direct", body.push_token)
        result = _active_service().register_live_activity(
            session_id=body.session_id,
            live_session_id=body.live_session_id,
            profile=body.profile,
            activity_id=body.activity_id,
            push_token=body.push_token,
            token_environment=body.environment,
        )
        return {**result, "token_fingerprint": _token_fingerprint(body.push_token)}
    except Exception as error:
        raise _api_error(error) from error


@router.put("/devices/{device_id}/preferences")
def update_preferences(device_id: str, body: PreferenceUpdate) -> dict[str, Any]:
    try:
        return _active_service().update_device_preferences(device_id, _preferences(body))
    except Exception as error:
        raise _api_error(error) from error


@router.post("/test")
def test_notification(body: TestRequest) -> dict[str, Any]:
    try:
        verdict = validate_target(body.target)
        if verdict is not True:
            raise ValueError(str(verdict))
        return _active_service().test_notification(body.target)
    except Exception as error:
        raise _api_error(error) from error


@router.get("/events")
def list_events(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    store = _active_service().store
    _clean_event_projection(store)
    rows = store.list_events(limit=limit, offset=offset)
    events = asyncio.run(
        HermesWorkspaceBackend(service=_active_service()).enrich_completion_events(rows)
    )
    return {
        "events": events,
        "next_offset": offset + len(rows) if len(rows) == limit else None,
    }


@router.post("/events/dismiss")
def dismiss_events(body: EventDismissRequest) -> dict[str, Any]:
    dismissed = _active_service().store.dismiss_events(
        event_ids=body.event_ids,
        event_types=body.event_types,
        created_before=body.created_before,
    )
    return {"dismissed": dismissed}


@router.get("/events/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    service = _active_service()
    event = service.store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    enriched = asyncio.run(
        HermesWorkspaceBackend(service=service).enrich_completion_events([event])
    )
    if not enriched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return enriched[0]


@router.patch("/events/{event_id}")
def set_event_state(event_id: str, body: EventStateRequest) -> dict[str, Any]:
    if not _active_service().store.set_event_state(
        event_id,
        is_read=body.is_read,
        is_pinned=body.is_pinned,
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return {
        "event_id": event_id,
        "is_read": body.is_read,
        "is_pinned": body.is_pinned,
    }


@router.delete("/events/{event_id}")
def dismiss_event(event_id: str) -> dict[str, Any]:
    if not _active_service().store.dismiss_event(event_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return {"dismissed": True, "event_id": event_id}


@router.get("/approvals/{approval_id}")
def get_approval(approval_id: str) -> dict[str, Any]:
    approval = _active_service().store.get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
    return approval


@router.post("/approvals/{approval_id}/respond")
def respond_approval(approval_id: str, body: ApprovalResponse) -> dict[str, Any]:
    service = _active_service()
    approval = service.store.get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
    if approval["request_digest"] != body.request_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval request mismatch",
        )
    try:
        accepted = service.store.respond_approval(approval_id, body.choice)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval is expired or already answered",
        )
    return {"accepted": True, "approval_id": approval_id, "choice": body.choice}


@router.post("/generative-ui/v2/forms/{request_id}/submit")
def submit_form(request_id: str, body: FormActionRequest) -> dict[str, Any]:
    service = _active_service()
    try:
        stored = service.store.get_form_request(request_id)
    except (ValueError, TypeError):
        return _action_response(request_id, body.idempotency_key, "error", "request_not_found")
    except Exception:
        return _action_response(request_id, body.idempotency_key, "error", "internal_error")
    if stored is None:
        return _action_response(request_id, body.idempotency_key, "error", "request_not_found")
    if not (
        hmac.compare_digest(str(stored["profile"]), body.owner.profile)
        and hmac.compare_digest(str(stored["session_id"]), body.owner.session_id)
    ):
        return _action_response(request_id, body.idempotency_key, "error", "owner_mismatch")
    try:
        encoded_body = body.model_dump(mode="json", by_alias=True)
        if len(
            json.dumps(
                encoded_body,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ) > 8_192:
            return _action_response(request_id, body.idempotency_key, "error", "payload_too_large")
        if body.submitted_at.tzinfo is None:
            raise GenerativeUIError("invalid_value", "submitted_at must include a timezone")
        values = validate_submission_values(stored["form_schema"], body.values)
        return service.store.submit_form_request(
            request_id=request_id,
            profile=body.owner.profile,
            session_id=body.owner.session_id,
            idempotency_key=body.idempotency_key,
            values=values,
            now=_clock(),
        )
    except GenerativeUIError as error:
        code = "payload_too_large" if error.code == "payload_too_large" else "invalid_value"
        return _action_response(request_id, body.idempotency_key, "error", code)
    except ValueError:
        return _action_response(request_id, body.idempotency_key, "error", "invalid_value")
    except Exception:
        return _action_response(request_id, body.idempotency_key, "error", "internal_error")


@router.get("/generative-ui/v2/forms/{request_id}/status")
def form_status(
    request_id: str,
    profile: str = Query(min_length=1, max_length=80),
    session_id: str = Query(min_length=1, max_length=180),
) -> dict[str, Any]:
    try:
        return _active_service().store.form_request_status(
            request_id,
            profile=profile,
            session_id=session_id,
            now=_clock(),
        )
    except ValueError:
        return _action_response(request_id, "", "error", "request_not_found")
    except Exception:
        return _action_response(request_id, "", "error", "internal_error")


def _preferences(body: PreferenceUpdate) -> dict[str, Any]:
    fields = body.model_fields_set
    result: dict[str, Any] = {}
    if "detail_mode" in fields:
        result["detail_mode"] = body.detail_mode
    if "lock_screen_previews" in fields:
        result["lock_screen_previews"] = body.lock_screen_previews
    if "enabled_types" in fields:
        enabled = sorted(set(body.enabled_types))
        unknown = set(enabled) - EVENT_TYPES
        if unknown:
            raise ValueError(f"Unsupported event types: {', '.join(sorted(unknown))}")
        result["enabled_types"] = enabled
    if "notifications_enabled" in fields:
        result["notifications_enabled"] = body.notifications_enabled
    if "priority_sound" in fields:
        result["priority_sound"] = body.priority_sound
    if "quiet_hours" in fields:
        quiet_hours = body.quiet_hours.model_dump() if body.quiet_hours else None
        if quiet_hours is not None and not all(
            _TIME.fullmatch(str(quiet_hours[key])) for key in ("start", "end")
        ):
            raise ValueError("quiet_hours must contain HH:MM start and end values")
        result["quiet_hours"] = quiet_hours
    if "timezone" in fields:
        timezone = body.timezone.strip() if body.timezone else None
        if timezone and not _ZONE.fullmatch(timezone):
            raise ValueError("timezone must be an IANA-style identifier")
        result["timezone"] = timezone
    if "preferences_version" in fields:
        result["preferences_version"] = body.preferences_version
    return result


def _active_service():
    return _service or get_service()


def _clean_event_projection(store: Any) -> None:
    now = _clock()
    store.dismiss_gateway_lifecycle_events(dismissed_at=now)
    store.dismiss_inactive_approval_events(now=now, dismissed_at=now)
    try:
        from tools.clarify_gateway import get_clarify_timeout

        clarify_timeout = int(get_clarify_timeout())
    except (ImportError, TypeError, ValueError):
        clarify_timeout = 3600
    if clarify_timeout > 0:
        store.dismiss_expired_attention(
            now - clarify_timeout,
            dismissed_at=now,
        )


def _active_workspace_git() -> WorkspaceGitService:
    global _workspace_git_service
    if _workspace_git_service is None:
        _workspace_git_service = WorkspaceGitService.from_environment(
            state_path=_WORKSPACE_GIT_STATE_PATH
        )
    return _workspace_git_service


def _active_attachment_store() -> AttachmentStore:
    global _attachment_store
    if _attachment_store is None:
        _attachment_store = AttachmentStore(data_path().with_name("attachments.sqlite3"))
    return _attachment_store


def _execute_workspace_git(
    operation: str,
    body: WorkspaceExecution,
    request: Request,
) -> dict[str, Any] | JSONResponse:
    try:
        return _active_workspace_git().execute(
            operation,
            body.model_dump(),
            connection_id=_connection_binding(request),
        )
    except WorkspaceGitError as error:
        return _workspace_git_error_response(error)


def _connection_binding(request: Request) -> str:
    # Authentication is enforced by the host before this plugin router. Bind the
    # confirmation to that opaque credential/session without persisting or
    # returning it. Client-supplied workspace data never participates.
    credential = request.headers.get("authorization") or request.headers.get("cookie") or "authenticated"
    peer = request.client.host if request.client else "local"
    return hashlib.sha256(f"{peer}\0{credential}".encode("utf-8")).hexdigest()


def _workspace_git_error_response(error: WorkspaceGitError) -> JSONResponse:
    mapping = {
        "INVALID_REQUEST": status.HTTP_400_BAD_REQUEST,
        "INVALID_PATH": status.HTTP_400_BAD_REQUEST,
        "UNSUPPORTED_PATH_ENCODING": status.HTTP_400_BAD_REQUEST,
        "OPERATION_NOT_ALLOWED": status.HTTP_403_FORBIDDEN,
        "PUBLIC_REPO_SAFETY_BLOCK": status.HTTP_403_FORBIDDEN,
        "WORKSPACE_NOT_ALLOWED": status.HTTP_404_NOT_FOUND,
        "STATUS_STALE": status.HTTP_409_CONFLICT,
        "BRANCH_MISMATCH": status.HTTP_409_CONFLICT,
        "UPSTREAM_REQUIRED": status.HTTP_409_CONFLICT,
        "WORKTREE_NOT_CLEAN": status.HTTP_409_CONFLICT,
        "WORKTREE_CONFLICTED": status.HTTP_409_CONFLICT,
        "IDEMPOTENCY_CONFLICT": status.HTTP_409_CONFLICT,
        "CONFIRMATION_INVALID": status.HTTP_409_CONFLICT,
        "OPERATION_IN_PROGRESS": status.HTTP_409_CONFLICT,
        "NON_FAST_FORWARD": status.HTTP_409_CONFLICT,
        "NOTHING_TO_STAGE": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "NOTHING_TO_COMMIT": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "NOTHING_TO_PUSH": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "NOTHING_TO_PULL": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "SECRET_SCAN_BLOCKED": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "GIT_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
        "REMOTE_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
        "GIT_OUTCOME_UNKNOWN": status.HTTP_503_SERVICE_UNAVAILABLE,
        "GIT_TIMEOUT": status.HTTP_504_GATEWAY_TIMEOUT,
    }
    return JSONResponse(status_code=mapping.get(error.code, 500), content=error.envelope())


def _groups(values: list[str]) -> list[str]:
    groups = sorted({value.strip() for value in values if value.strip()})
    if any(validate_target(f"group:{value}") is not True for value in groups):
        raise ValueError("Group identifiers contain unsupported characters")
    return groups


def _public_device(device: dict[str, Any]) -> dict[str, Any]:
    endpoint = str(device.get("endpoint_id") or "")
    return {
        "device_id": device.get("device_id"),
        "provider": device.get("provider"),
        "token_environment": device.get("token_environment"),
        "token_fingerprint": _token_fingerprint(endpoint),
        "label": device.get("label"),
        "groups": device.get("groups") or [],
        "preferences": device.get("preferences") or {},
        "revoked": bool(device.get("revoked")),
    }


def _token_fingerprint(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _validate_push_token(provider: str, token: str) -> None:
    if provider == "managed" and not _EXPO_TOKEN.fullmatch(token):
        raise ValueError("Managed devices require a valid Expo push token")
    if provider == "direct" and not _APNS_TOKEN.fullmatch(token):
        raise ValueError("Direct devices require a valid native APNs token")


def _api_error(error: Exception) -> HTTPException:
    if isinstance(error, ValueError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_public_error(str(error)),
        )
    if isinstance(error, DeliveryError):
        code = _public_error(error.code)
        response_status = status.HTTP_503_SERVICE_UNAVAILABLE if error.retryable else status.HTTP_400_BAD_REQUEST
        return HTTPException(status_code=response_status, detail=f"Push provider error: {code}")
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Loopdy request failed",
    )


def _public_error(value: str) -> str:
    text = " ".join(str(value or "Loopdy request failed").split())[:300]
    text = re.sub(r"(?:Exponent|Expo)PushToken\[[^\]]+\]", "[redacted token]", text)
    text = re.sub(r"\b[0-9a-fA-F]{64,}\b", "[redacted token]", text)
    text = re.sub(r"(?:^|\s)/(?:[^\s/]+/)+[^\s]+", " [redacted path]", text)
    return text or "Loopdy request failed"


_ACTION_MESSAGES = {
    "request_not_found": "Form request was not found.",
    "owner_mismatch": "Form request belongs to another session.",
    "invalid_value": "One or more form values are invalid.",
    "payload_too_large": "Form response exceeds the byte limit.",
    "internal_error": "Form response could not be processed.",
}


def _action_response(request_id: str, idempotency_key: str, state: str, code: str) -> dict[str, Any]:
    safe_request_id = (
        request_id
        if re.fullmatch(r"[0-9a-f]{32}", str(request_id or ""))
        else "0" * 32
    )
    return {
        "schema": "loopdy.generative_ui.action_response",
        "version": 2,
        "request_id": safe_request_id,
        "idempotency_key": idempotency_key,
        "state": state,
        "code": code,
        "message": _ACTION_MESSAGES[code],
    }
