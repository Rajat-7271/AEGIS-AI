"""Hunt search & saved-searches API (services/api).

Backs the console's /hunt page:
- Saved searches panel: GET /saved, POST /saved, DELETE /saved/{id}
- Free-form hunt search runner: POST /search
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser
from app.api.v1.endpoints.cases import _agents_proxy
from app.db.rls import TenantDBSession
from app.models.saved_search import SavedSearch

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/hunt", tags=["hunt"])


# ────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ────────────────────────────────────────────────────────────────────────────


class SavedSearchCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    query: str = Field(..., min_length=1)
    language: str = Field(default="lucene")


class SavedSearchOut(BaseModel):
    id: str
    name: str
    query: str
    language: str
    createdAt: str
    pinned: bool = False


class SavedSearchListResponse(BaseModel):
    searches: list[SavedSearchOut]


class HuntQuery(BaseModel):
    query: str
    language: str = "lucene"
    startTime: str | None = None
    endTime: str | None = None
    timeRange: str | None = "24h"
    indices: list[str] | None = None
    limit: int = 100


class HuntHit(BaseModel):
    id: str
    timestamp: str
    source: str
    event_type: str = "security_event"
    severity: str = "medium"
    raw: dict[str, Any] = Field(default_factory=dict)
    fields: dict[str, Any] = Field(default_factory=dict)
    highlights: list[str] | None = None
    highlight: str | None = None


class HuntResponse(BaseModel):
    query: str
    total: int
    took: int
    took_ms: int
    hits: list[HuntHit]
    source: Literal["sample", "live"] = "sample"
    notice: str | None = None


# ────────────────────────────────────────────────────────────────────────────
# Synthetic telemetry generator (honest fallback when event lake / agents absent)
# ────────────────────────────────────────────────────────────────────────────


def _synthetic_hits(query: str, limit: int) -> list[dict[str, Any]]:
    """Return illustrative sample telemetry events."""
    templates = [
        {
            "source": "crowdstrike",
            "event_type": "ProcessCreation",
            "severity": "high",
            "fields": {
                "host": "WORKSTATION-042",
                "user": "john.doe",
                "process.name": "powershell.exe",
                "process.command_line": f"powershell.exe -nop -w hidden -enc {query}",
            },
            "raw": {
                "process_name": "powershell.exe",
                "parent_name": "explorer.exe",
                "cmdline": f"powershell.exe -nop -w hidden -enc {query}",
                "user": "DOMAIN\\analyst",
                "host": "WS-DEV-01",
            },
        },
        {
            "source": "defender",
            "event_type": "SignInLog",
            "severity": "medium",
            "fields": {
                "host": "SERVER-DC01",
                "user": "svc_admin",
                "ipAddress": "192.0.2.42",
            },
            "raw": {
                "userPrincipalName": "user@corp.example",
                "ipAddress": "192.0.2.42",
                "location": "US",
                "appDisplayName": "Microsoft 365",
                "resultType": "0",
            },
        },
        {
            "source": "splunk",
            "event_type": "AssumeRole",
            "severity": "info",
            "fields": {
                "host": "AWS-PROD-IAM",
                "user": "terraform",
                "role": "arn:aws:iam::123456789:role/Admin",
            },
            "raw": {
                "eventName": "AssumeRole",
                "sourceIPAddress": "10.0.0.100",
                "userAgent": "aws-sdk-python",
                "requestParameters": {"roleArn": "arn:aws:iam::123456789:role/Admin"},
            },
        },
    ]
    now = datetime.now(UTC)
    hits = []
    hit_limit = max(1, min(limit, 50))
    for i in range(min(hit_limit, 5)):
        t = templates[i % len(templates)]
        hits.append(
            {
                "id": f"r-00{i + 1}",
                "timestamp": now.isoformat(),
                "source": t["source"],
                "event_type": t["event_type"],
                "severity": t["severity"],
                "fields": t["fields"],
                "raw": t["raw"],
                "highlights": [query] if query else [],
                "highlight": query if query else None,
            }
        )
    return hits


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("/saved", response_model=SavedSearchListResponse)
async def list_saved_searches(
    user: AuthUser,
    db: TenantDBSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> SavedSearchListResponse:
    """This tenant's saved hunt searches, newest first."""
    int_limit = limit if isinstance(limit, int) else 50
    stmt = select(SavedSearch).where(SavedSearch.tenant_id == user.tenant_id).order_by(SavedSearch.updated_at.desc()).limit(int_limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return SavedSearchListResponse(
        searches=[
            SavedSearchOut(
                id=str(row.id),
                name=row.name,
                query=row.query,
                language=row.backend or "lucene",
                createdAt=row.created_at.astimezone(UTC).isoformat() if row.created_at else datetime.now(UTC).isoformat(),
                pinned=False,
            )
            for row in rows
        ]
    )


@router.post("/saved", response_model=SavedSearchOut, status_code=status.HTTP_201_CREATED)
async def save_search(
    data: SavedSearchCreate,
    user: AuthUser,
    db: TenantDBSession,
) -> SavedSearchOut:
    """Persist a new saved hunt search for the caller's tenant."""
    name = data.name.strip()
    query = data.query.strip()
    if not name:
        raise HTTPException(
            status_code=422,
            detail="Name cannot be empty",
        )
    if not query:
        raise HTTPException(
            status_code=422,
            detail="Query cannot be empty",
        )

    now = datetime.now(UTC)
    row = SavedSearch(
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        name=name,
        query=query,
        backend=data.language or "lucene",
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    return SavedSearchOut(
        id=str(row.id),
        name=row.name,
        query=row.query,
        language=row.backend or "lucene",
        createdAt=row.created_at.astimezone(UTC).isoformat() if row.created_at else now.isoformat(),
        pinned=False,
    )


@router.delete("/saved/{search_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_search(
    search_id: str,
    user: AuthUser,
    db: TenantDBSession,
) -> None:
    """Delete a saved hunt search belonging to the caller's tenant."""
    try:
        parsed_id = uuid.UUID(search_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved search not found",
        ) from None

    stmt = select(SavedSearch).where(
        SavedSearch.tenant_id == user.tenant_id,
        SavedSearch.id == parsed_id,
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved search not found",
        )

    await db.delete(row)
    await db.commit()


@router.post("/search", response_model=HuntResponse)
async def hunt_search(
    query: HuntQuery,
    user: AuthUser,
) -> HuntResponse:
    """Execute a hunt query and return matching telemetry events."""
    start = time.monotonic()

    # If the agents service is reachable, proxy the hunt search
    try:
        proxy_res = await _agents_proxy(
            "POST",
            "/api/v1/hunt/search",
            json={
                "query": query.query,
                "language": query.language,
                "limit": query.limit,
                "tenant_id": str(user.tenant_id),
            },
            timeout=15.0,
        )
        if proxy_res.status_code == 200:
            data = proxy_res.json()
            # Ensure both took and took_ms are populated
            took = data.get("took", data.get("took_ms", 0))
            data["took"] = took
            data["took_ms"] = took
            return HuntResponse(**data)
    except Exception as exc:
        logger.debug("agents_proxy_hunt_search_unavailable", error=str(exc))

    took_ms = int((time.monotonic() - start) * 1000)
    raw_hits = _synthetic_hits(query.query, query.limit)
    return HuntResponse(
        query=query.query,
        total=len(raw_hits),
        took=took_ms,
        took_ms=took_ms,
        hits=[HuntHit(**h) for h in raw_hits],
        source="sample",
        notice=(
            "These are illustrative sample events, not results from your telemetry. "
            "Run the hunt from /hunt against a configured data source for real hits."
        ),
    )
