"""Mounted only by Hermes' supported authenticated plugin router loader."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from .managed_notifications import ManagedNotificationError, get_managed_notifications

router = APIRouter(prefix="/notifications")
_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_PROFILE = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"


class VersionedBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: StrictInt = Field(ge=1, le=1)


class EnrollmentBody(VersionedBody):
    idempotencyKey: str = Field(pattern=_UUID)
    grantId: str = Field(pattern=_UUID)


class SessionBody(VersionedBody):
    profile: str = Field(pattern=_PROFILE)
    sessionId: str = Field(pattern=_ID)
    enabled: StrictBool


class WorkBody(VersionedBody):
    profile: str = Field(pattern=_PROFILE)
    sessionId: str = Field(pattern=_ID)


class ActivityBody(VersionedBody):
    profile: str = Field(pattern=_PROFILE)
    sessionId: str = Field(pattern=_ID)
    sessionReference: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    leaseExpires: StrictInt = Field(gt=0, le=9_999_999_999)
    turnId: str | None = Field(default=None, pattern=_ID)


def _call(operation, *args):
    try:
        return operation(*args)
    except ManagedNotificationError as error:
        raise HTTPException(status_code=error.status, detail={"code": error.code}) from None
    except (OSError, ValueError):
        raise HTTPException(status_code=503, detail={"code": "notification_service_unavailable"}) from None


# Synchronous handlers run in FastAPI's threadpool: no blocking HTTPS on the
# Hermes event loop. Authentication is the stock host middleware, not an account
# bearer forwarded from the app. No secret authority is accepted in these bodies.
@router.get("/capabilities")
def capabilities():
    return _call(lambda: get_managed_notifications().capabilities())


@router.post("/enroll")
def enroll(body: EnrollmentBody):
    return _call(lambda: get_managed_notifications().enroll(body.grantId, body.idempotencyKey))


@router.get("/enrollments/{grant_id}")
def enrollment(grant_id: str):
    return _call(lambda: get_managed_notifications().enrollment(grant_id))


@router.delete("/enrollments/{grant_id}")
def remove(grant_id: str):
    return _call(lambda: get_managed_notifications().remove(grant_id))


@router.put("/enrollments/{grant_id}/sessions")
def subscribe(grant_id: str, body: SessionBody):
    return _call(lambda: get_managed_notifications().subscribe(grant_id, body.profile, body.sessionId, body.enabled))


@router.post("/enrollments/{grant_id}/work")
def work_snapshot(grant_id: str, body: WorkBody):
    return _call(lambda: get_managed_notifications().work_snapshot(grant_id, body.profile, body.sessionId))


@router.get("/enrollments/{grant_id}/events/{event_id}")
def event(grant_id: str, event_id: str):
    return _call(lambda: get_managed_notifications().event(grant_id, event_id))


@router.put("/enrollments/{grant_id}/live-activities/{activity_id}")
def activity(grant_id: str, activity_id: str, body: ActivityBody):
    return _call(lambda: get_managed_notifications().subscribe_activity(grant_id, activity_id, body.profile, body.sessionId, body.sessionReference, body.leaseExpires, body.turnId))


@router.delete("/enrollments/{grant_id}/live-activities/{activity_id}")
def remove_activity(grant_id: str, activity_id: str):
    return _call(lambda: get_managed_notifications().remove_activity(grant_id, activity_id))
