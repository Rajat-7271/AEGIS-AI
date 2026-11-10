"""Minimal Windows Security ingestion for Kafka-free deployments.

This route deliberately stores only the metadata exported by the Windows pilot.
A tenant-specific, revocable connector-push inbox token authenticates writes.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, require_permission
from app.db.database import get_db
from app.db.rls import set_rls_context
from app.models.inbox import TenantInboxToken

router = APIRouter(prefix="/windows-security", tags=["windows-security"])
Session = Annotated[AsyncSession, Depends(get_db)]
_ALLOWED = {4624, 4625, 4672, 4688, 4720, 1102}


class WindowsEvent(BaseModel):
    external_id: str = Field(min_length=1, max_length=512)
    severity: str = Field(max_length=32)
    hostname: str = Field(min_length=1, max_length=255)
    created_at: datetime
    raw_event: dict


class WindowsBatch(BaseModel):
    connector_id: uuid.UUID
    connector_type: str
    source_format: str
    events: list[WindowsEvent] = Field(min_length=1, max_length=500)


async def _verify_windows_ingest_token(db: AsyncSession, authorization: str | None, tenant_header: str | None, x_signature: str | None, raw: bytes) -> uuid.UUID:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Connector-push token required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token or len(token) > 80:
        raise HTTPException(401, "Invalid ingest credential")
    if not tenant_header:
        raise HTTPException(400, "Tenant header required")
    try:
        claimed = uuid.UUID(tenant_header)
    except ValueError:
        raise HTTPException(400, "Invalid tenant UUID") from None
    result = await db.execute(select(TenantInboxToken).where(
        TenantInboxToken.tenant_id == claimed,
        TenantInboxToken.token == token,
        TenantInboxToken.revoked_at.is_(None),
        TenantInboxToken.template_id == "connector-push",
    ))
    credential = result.scalar_one_or_none()
    if credential is None:
        raise HTTPException(401, "Invalid ingest credential")
    if claimed != credential.tenant_id:
        raise HTTPException(403, "Token is not scoped to requested tenant")
    if len(raw) > 2_000_000:
        raise HTTPException(413, "Batch too large")
    if credential.hmac_secret:
        expected = hmac.new(credential.hmac_secret.encode(), raw, hashlib.sha256).hexdigest()
        supplied = (x_signature or "").removeprefix("sha256=")
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(401, "Invalid body signature")
    return credential.tenant_id


@router.post("/batch")
async def ingest_windows(
    request: Request,
    db: Session,
    authorization: Annotated[str | None, Header()] = None,
    x_signature: Annotated[str | None, Header()] = None,
    tenant_header: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
):
    raw = await request.body()
    tenant_id = await _verify_windows_ingest_token(db, authorization, tenant_header, x_signature, raw)
    try:
        batch = WindowsBatch.model_validate_json(raw)
    except ValueError:
        raise HTTPException(422, "Invalid Windows event batch") from None
    if batch.connector_type != "windows_event" or batch.source_format != "raw_json":
        raise HTTPException(422, "Unsupported event format")
    await set_rls_context(db, tenant_id)
    for event in batch.events:
        system = event.raw_event.get("System")
        if not isinstance(system, dict) or not {"System", "EventData"}.issubset(event.raw_event) or event.raw_event["EventData"] != {}:
            raise HTTPException(422, "Unexpected event structure")
        if system.get("Channel") != "Security" or type(system.get("EventID")) is not int or system["EventID"] not in _ALLOWED:
            raise HTTPException(422, "Unsupported Security event")
        if type(system.get("EventRecordID")) is not int or system["EventRecordID"] < 0:
            raise HTTPException(422, "Invalid record ID")
        if system.get("Computer") != event.hostname or not isinstance(system.get("Provider"), str):
            raise HTTPException(422, "Inconsistent host or provider")
        if set(system) != {"EventID", "Channel", "Computer", "EventRecordID", "TimeCreated", "Provider"}:
            raise HTTPException(422, "Unexpected Security metadata")
        try:
            source_time = datetime.fromisoformat(system["TimeCreated"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise HTTPException(422, "Invalid source timestamp") from None
        if event.created_at != source_time:
            raise HTTPException(422, "Inconsistent event timestamp")
        # Stable across retries; tenant scope is part of the primary key.
        event_id = uuid.uuid5(uuid.NAMESPACE_URL, event.external_id)
        await db.execute(text("""
            INSERT INTO windows_security_events
                (tenant_id,event_id,connector_id,event_time,event_code,hostname,severity,provider,record_id)
            VALUES (:tenant,:id,:connector,:time,:code,:host,:severity,:provider,:record)
            ON CONFLICT (tenant_id,event_id) DO NOTHING
        """), dict(tenant=tenant_id, id=event_id,
                   connector=batch.connector_id, time=event.created_at,
                   code=system["EventID"], host=event.hostname,
                   severity=event.severity, provider=system["Provider"],
                   record=system["EventRecordID"]))
    await db.commit()
    return {"accepted": len(batch.events), "rejected": 0}


@router.get("/events")
async def list_windows_events(
    user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: Session,
    limit: int = 100,
):
    if not 1 <= limit <= 500:
        raise HTTPException(422, "Limit must be between 1 and 500")
    await set_rls_context(db, user.tenant_id)
    result = await db.execute(text("""
        SELECT event_time, severity, hostname, event_code, provider, record_id
        FROM windows_security_events
        WHERE tenant_id = :tenant
        ORDER BY event_time DESC LIMIT :limit
    """), {"tenant": user.tenant_id, "limit": limit})
    rows = [[v.isoformat() if isinstance(v, datetime) else v for v in row] for row in result]
    return {"columns": ["event_time", "severity", "hostname", "event_code", "provider", "record_id"],
            "rows": rows, "row_count": len(rows)}
